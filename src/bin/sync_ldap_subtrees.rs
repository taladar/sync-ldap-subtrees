#![doc = include_str!("../../README.md")]

use ldap_types::basic::LDAPEntry;
use ldap_types::filter::search_filter_parser;
use ldap_utils::apply_ldap_operations;
use ldap_utils::diff_entries;
use ldap_utils::search_entries;
use ldap_utils::{
    connect_with_parameters, parse_scope, query_ldap_schema, query_root_dse,
    toml_connect_parameters,
};

use tracing::instrument;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use std::collections::HashMap;

use chumsky::Parser as _;

/// Command-line options
#[derive(clap::Parser, Debug)]
#[clap(name = clap::crate_name!(),
       about = clap::crate_description!(),
       author = clap::crate_authors!(),
       version = clap::crate_version!(),
       )]
#[expect(
    clippy::struct_excessive_bools,
    reason = "This models the command line interface for clap, we can not just refactor this into a different structure"
)]
struct Options {
    /// do not perform any changes, just show (in logs) what would be done
    #[clap(
        long,
        help = "do not perform any changes, just show (in logs) what would be done"
    )]
    dry_run: bool,

    /// add entries missing at the destination
    #[clap(long, help = "Add entries missing at the destination")]
    add: bool,

    /// update entries with differing attributes and/or objectclasses at the destination
    #[clap(
        long,
        help = "Update entries with differing attributes and/or objectclasses at the destination"
    )]
    update: bool,

    /// delete entries at the destination not present at the source
    #[clap(
        long,
        help = "Delete entries at the destination not present at the source"
    )]
    delete: bool,

    /// Name of TOML file describing the CA certificate, client certificate, client key and LDAP URI for the source LDAP server
    #[clap(
        long,
        help = "Name of TOML file describing the CA certificate, client certificate, client key and LDAP URI for the source LDAP server"
    )]
    source_ldap_server: std::path::PathBuf,

    /// base DN for the search to perform on the source LDAP server
    #[clap(
        long,
        help = "base DN for the search to perform on the source LDAP server"
    )]
    source_search_base: std::string::String,

    /// Name of TOML file describing the CA certificate, client certificate, client key and LDAP URI for the destination LDAP server
    #[clap(
        long,
        help = "Name of TOML file describing the CA certificate, client certificate, client key and LDAP URI for the destination LDAP server"
    )]
    destination_ldap_server: std::path::PathBuf,

    /// base DN for the search to perform on the destination LDAP server
    #[clap(
        long,
        help = "base DN for the search to perform on the destination LDAP server"
    )]
    destination_search_base: std::string::String,

    /// scope for the search
    #[clap(long, value_parser = parse_scope)]
    search_scope: ldap3::Scope,

    /// LDAP search filter for the search on the source LDAP server
    /// for the destination LDAP server the DN-valued attributes are
    /// automatically transformed to the destination base DN
    #[clap(
        long,
        help = "LDAP search filter for the search on the source LDAP server, for the destination LDAP server the DN-valued attributes are automatically transformed to the destination base DN"
    )]
    search_filter: std::string::String,

    /// if specified only transfer these attributes
    #[clap(long = "attribute", number_of_values = 1)]
    attributes: Vec<std::string::String>,

    /// if specified ignore these object classes when transferring data (useful e.g. to avoid transferring passwords or similar local information)
    /// this does not automatically ignore any attributes since each attribute could be required by more than one object class
    #[clap(
        long = "ignore-object-class",
        help = "if specified ignore these object classes when transferring data (useful e.g. to avoid transferring passwords or similar local information)"
    )]
    ignore_object_classes: Vec<std::string::String>,

    /// if specified ignore these attributes when transferring data (useful e.g. to avoid transferring passwords or similar local information)
    #[clap(
        long = "ignore-attribute",
        help = "if specified ignore these attributes when transferring data (useful e.g. to avoid transferring passwords or similar local information)"
    )]
    ignore_attributes: Vec<std::string::String>,

    /// if this is specified all children of matched entries are also transferred, this is necessary because those children themselves might not have any objectclasses or attributes to use in the search filter
    #[clap(
        long,
        help = "if this is specified all children of matched entries are also transferred, this is necessary because those children themselves might not have any objectclasses or attributes to use in the search filter"
    )]
    include_children: bool,
}

use thiserror::Error;

/// All errors that can occur during the sync
#[derive(Debug, Error)]
enum SyncLdapSubtreesError {
    #[error(transparent)]
    /// Error originating from the `clap` crate for command-line argument parsing.
    Clap(#[from] clap::Error),
    #[error(transparent)]
    /// Error originating from parsing the TOML configuration file.
    TomlConfig(#[from] ldap_utils::TomlConfigError),
    #[error(transparent)]
    /// Error originating from connecting to the LDAP server.
    Connect(#[from] ldap_utils::ConnectError),
    #[error(transparent)]
    /// Error originating from querying the LDAP schema.
    LdapSchema(#[from] ldap_utils::LdapSchemaError),
    #[error(transparent)]
    /// Error originating from performing LDAP operations.
    LdapOperations(#[from] ldap_utils::LdapOperationError),
    #[error("failed to parse search filter: {0}")]
    /// Error indicating a failure to parse the provided search filter.
    SearchFilterParsing(String),
    #[error("missing LDAP schema")]
    /// Error indicating that the LDAP schema could not be retrieved.
    MissingLdapSchema,
}

#[tokio::main]
async fn main() {
    FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    match do_sync().await {
        Ok(()) => (),
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    }
}

/// main logic other than logging init and error printing
#[instrument]
async fn do_sync() -> Result<(), SyncLdapSubtreesError> {
    let options = <Options as clap::Parser>::try_parse()?;
    tracing::debug!("{:#?}", options);

    let source_connect_parameters = toml_connect_parameters(options.source_ldap_server.to_owned())?;
    tracing::debug!(
        "Source connect parameters\n{:#?}",
        source_connect_parameters
    );
    let (mut source_ldap, source_base_dn) =
        connect_with_parameters(source_connect_parameters).await?;
    tracing::debug!("Source base DN {:#?}", source_base_dn);
    let source_root_dse = query_root_dse(&mut source_ldap).await?;
    tracing::debug!("Source root DSE {:#?}", source_root_dse);
    let source_ldap_schema = query_ldap_schema(&mut source_ldap)
        .await?
        .ok_or(SyncLdapSubtreesError::MissingLdapSchema)?;
    tracing::debug!("Source LDAP schema {:#?}", source_ldap_schema);

    let destination_connect_parameters =
        toml_connect_parameters(options.destination_ldap_server.to_owned())?;
    tracing::debug!(
        "Destination connect parameters\n{:#?}",
        destination_connect_parameters
    );
    let (mut destination_ldap, destination_base_dn) =
        connect_with_parameters(destination_connect_parameters).await?;
    tracing::debug!("Destination base DN {:#?}", destination_base_dn);
    let destination_root_dse = query_root_dse(&mut destination_ldap).await?;
    tracing::debug!("Destination root DSE {:#?}", destination_root_dse);
    let destination_ldap_schema = query_ldap_schema(&mut destination_ldap)
        .await?
        .ok_or(SyncLdapSubtreesError::MissingLdapSchema)?;
    tracing::debug!("Destination LDAP schema {:#?}", destination_ldap_schema);

    let source_search_filter = search_filter_parser()
        .parse(&options.search_filter)
        .into_result()
        .map_err(|e| SyncLdapSubtreesError::SearchFilterParsing(format!("{e:#?}")))?;
    tracing::debug!("Source search filter: {:#?}", source_search_filter);
    let destination_search_filter = source_search_filter.transform_base_dns(
        &source_base_dn,
        &destination_base_dn,
        &source_ldap_schema,
    );
    tracing::debug!(
        "Destination search filter: {:#?}",
        destination_search_filter
    );
    tracing::debug!(
        "Search filter as passed in:          {}",
        &options.search_filter
    );
    let source_search_filter = source_search_filter.to_string();
    let destination_search_filter = destination_search_filter.to_string();
    tracing::debug!(
        "Source search filter as string:      {}",
        source_search_filter
    );
    tracing::debug!(
        "Destination search filter as string: {}",
        destination_search_filter
    );

    let mut source_entries: HashMap<String, LDAPEntry> = HashMap::new();
    tracing::debug!("Performing base query for source entries");
    search_entries(
        &mut source_ldap,
        &source_base_dn,
        &options.source_search_base,
        options.search_scope,
        &source_search_filter,
        options.attributes.as_slice(),
        &mut source_entries,
    )
    .await?;

    if options.include_children {
        let source_base_query_dns = source_entries.keys().cloned().collect::<Vec<String>>();
        for dn in &source_base_query_dns {
            tracing::debug!("Performing subtree query for source entry {}", &dn);
            search_entries(
                &mut source_ldap,
                &source_base_dn,
                dn,
                ldap3::Scope::Subtree,
                "(objectClass=*)",
                options.attributes.as_slice(),
                &mut source_entries,
            )
            .await?;
        }
    }

    let mut destination_entries: HashMap<String, LDAPEntry> = HashMap::new();
    tracing::debug!("Performing base query for destination entries");
    search_entries(
        &mut destination_ldap,
        &destination_base_dn,
        &options.destination_search_base,
        options.search_scope,
        &destination_search_filter,
        options.attributes.as_slice(),
        &mut destination_entries,
    )
    .await?;

    if options.include_children {
        let destination_base_query_dns =
            destination_entries.keys().cloned().collect::<Vec<String>>();
        for dn in &destination_base_query_dns {
            tracing::debug!("Performing subtree query for destination entry {}", &dn);
            search_entries(
                &mut destination_ldap,
                &destination_base_dn,
                dn,
                ldap3::Scope::Subtree,
                "(objectClass=*)",
                options.attributes.as_slice(),
                &mut destination_entries,
            )
            .await?;
        }
    }

    tracing::debug!("Source entries:\n{:#?}", source_entries);
    tracing::debug!("Destination entries:\n{:#?}", destination_entries);

    let ldap_operations = diff_entries(
        &source_entries,
        &destination_entries,
        &source_base_dn,
        &destination_base_dn,
        &options.ignore_object_classes,
        &options.ignore_attributes,
        &source_ldap_schema,
        options.add,
        options.update,
        options.delete,
    )?;

    tracing::debug!("Operations to apply: {:#?}", ldap_operations);
    // TODO: abort sync if schemas differ between source and destination (optionally?)
    // TODO: optionally specify details of operation in a toml file instead of the CLI (I think clap or structopt has some options there?)

    // apparently some (e.g. delete) operations do not work properly with no-op control (e.g. the
    // object is gone from further searches until the next slapd restart)
    //apply_ldap_operations(
    //    &mut destination_ldap,
    //    &destination_base_dn,
    //    &ldap_operations,
    //    vec![noop_control()],
    //)
    //.await?;

    if !options.dry_run {
        apply_ldap_operations(
            &mut destination_ldap,
            &destination_base_dn,
            &ldap_operations,
            vec![],
        )
        .await?;
    }

    Ok(())
}
