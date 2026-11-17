#![doc = include_str!("../../README.md")]

use ldap_types::basic::{LDAPEntry, LDAPOperation};
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

    /// keep applying the remaining operations when one fails, log each failure
    /// and exit with an error at the end if any failed
    #[clap(
        long,
        help = "Keep applying the remaining operations when one fails (e.g. a constraint violation on a single entry), log each failure and exit with an error at the end if any failed"
    )]
    continue_on_error: bool,

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
    #[error("error reading the {server} LDAP server config {path}: {source}")]
    /// Error originating from parsing the TOML configuration file.
    TomlConfig {
        /// which server the config is for (source or destination)
        server: &'static str,
        /// the path of the config file
        path: std::path::PathBuf,
        /// the error
        #[source]
        source: Box<ldap_utils::TomlConfigError>,
    },
    #[error("error connecting to the {server} LDAP server {url} (config {path}): {source}")]
    /// Error originating from connecting to the LDAP server.
    Connect {
        /// which server (source or destination)
        server: &'static str,
        /// the LDAP URL from the config
        url: String,
        /// the path of the config file
        path: std::path::PathBuf,
        /// the error
        #[source]
        source: Box<ldap_utils::ConnectError>,
    },
    #[error("error querying the LDAP schema of the {server} LDAP server: {source}")]
    /// Error originating from querying the LDAP schema.
    LdapSchema {
        /// which server (source or destination)
        server: &'static str,
        /// the error
        #[source]
        source: Box<ldap_utils::LdapSchemaError>,
    },
    #[error("error on the {server} LDAP server: {source}")]
    /// Error originating from performing LDAP operations on one of the servers.
    LdapOperationsOn {
        /// which server (source or destination)
        server: &'static str,
        /// the error
        #[source]
        source: Box<ldap_utils::LdapOperationError>,
    },
    #[error(transparent)]
    /// Error originating from LDAP operations not specific to one server
    /// (e.g. diffing the entries).
    LdapOperations(#[from] ldap_utils::LdapOperationError),
    #[error("failed to parse search filter '{filter}': {errors}")]
    /// Error indicating a failure to parse the provided search filter.
    SearchFilterParsing {
        /// the search filter as given on the command line
        filter: String,
        /// the parse errors
        errors: String,
    },
    #[error("the {server} LDAP server did not return an LDAP schema")]
    /// Error indicating that the LDAP schema could not be retrieved.
    MissingLdapSchema {
        /// which server (source or destination)
        server: &'static str,
    },
    #[error("{failed} of {total} LDAP operations failed, see the log for the individual failures")]
    /// Error indicating that some operations failed with --continue-on-error
    OperationsFailed {
        /// number of operations that failed
        failed: usize,
        /// number of operations that were attempted
        total: usize,
    },
}

/// short description of an LDAP operation for log messages
fn describe_operation(operation: &LDAPOperation, base_dn: &str) -> String {
    match operation {
        LDAPOperation::Add(LDAPEntry { dn, .. }) => format!("add {dn},{base_dn}"),
        LDAPOperation::Delete { dn } => format!("delete {dn},{base_dn}"),
        LDAPOperation::Modify { dn, .. } => format!("modify {dn},{base_dn}"),
    }
}

#[tokio::main]
async fn main() {
    FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    log_panics::init();
    #[expect(
        clippy::print_stderr,
        reason = "This is the final print in our error chain and we already log this with tracing above but depending on log level the tracing output is not seen by the user"
    )]
    match do_sync().await {
        Ok(()) => (),
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// name of the source server in messages
const SOURCE: &str = "source";
/// name of the destination server in messages
const DESTINATION: &str = "destination";

/// construct a function wrapping an LDAP operation error with the server it
/// occurred on
fn on_server(
    server: &'static str,
) -> impl FnOnce(ldap_utils::LdapOperationError) -> SyncLdapSubtreesError {
    move |source| SyncLdapSubtreesError::LdapOperationsOn {
        server,
        source: Box::new(source),
    }
}

/// connect to one of the LDAP servers and query its root DSE and schema
async fn connect_and_query_schema(
    server: &'static str,
    config_path: &std::path::Path,
) -> Result<(ldap3::Ldap, String, ldap_types::schema::LDAPSchema), SyncLdapSubtreesError> {
    let connect_parameters = toml_connect_parameters(config_path.to_owned()).map_err(|source| {
        SyncLdapSubtreesError::TomlConfig {
            server,
            path: config_path.to_owned(),
            source: Box::new(source),
        }
    })?;
    tracing::debug!("{server} connect parameters\n{:#?}", connect_parameters);
    let url = connect_parameters.url.clone();
    let (mut ldap, base_dn) =
        connect_with_parameters(connect_parameters)
            .await
            .map_err(|source| SyncLdapSubtreesError::Connect {
                server,
                url,
                path: config_path.to_owned(),
                source: Box::new(source),
            })?;
    tracing::debug!("{server} base DN {:#?}", base_dn);
    let root_dse = query_root_dse(&mut ldap).await.map_err(on_server(server))?;
    tracing::debug!("{server} root DSE {:#?}", root_dse);
    let ldap_schema = query_ldap_schema(&mut ldap)
        .await
        .map_err(|source| SyncLdapSubtreesError::LdapSchema {
            server,
            source: Box::new(source),
        })?
        .ok_or(SyncLdapSubtreesError::MissingLdapSchema { server })?;
    tracing::debug!("{server} LDAP schema {:#?}", ldap_schema);
    Ok((ldap, base_dn, ldap_schema))
}

/// main logic other than logging init and error printing
#[instrument]
async fn do_sync() -> Result<(), SyncLdapSubtreesError> {
    let options = <Options as clap::Parser>::try_parse()?;
    tracing::debug!("{:#?}", options);

    let (mut source_ldap, source_base_dn, source_ldap_schema) =
        connect_and_query_schema(SOURCE, &options.source_ldap_server).await?;
    let (mut destination_ldap, destination_base_dn, _destination_ldap_schema) =
        connect_and_query_schema(DESTINATION, &options.destination_ldap_server).await?;

    let source_search_filter = search_filter_parser()
        .parse(&options.search_filter)
        .into_result()
        .map_err(|e| SyncLdapSubtreesError::SearchFilterParsing {
            filter: options.search_filter.clone(),
            errors: format!("{e:#?}"),
        })?;
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
    .await
    .map_err(on_server(SOURCE))?;

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
            .await
            .map_err(on_server(SOURCE))?;
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
    .await
    .map_err(on_server(DESTINATION))?;

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
            .await
            .map_err(on_server(DESTINATION))?;
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
        if options.continue_on_error {
            // one operation at a time, so a failing one does not stop the rest
            let mut failed = 0_usize;
            for operation in &ldap_operations {
                if let Err(e) = apply_ldap_operations(
                    &mut destination_ldap,
                    &destination_base_dn,
                    std::slice::from_ref(operation),
                    vec![],
                )
                .await
                {
                    failed = failed.saturating_add(1);
                    tracing::error!(
                        "Failed to {}: {e}",
                        describe_operation(operation, &destination_base_dn)
                    );
                }
            }
            if failed > 0 {
                return Err(SyncLdapSubtreesError::OperationsFailed {
                    failed,
                    total: ldap_operations.len(),
                });
            }
        } else {
            apply_ldap_operations(
                &mut destination_ldap,
                &destination_base_dn,
                &ldap_operations,
                vec![],
            )
            .await
            .map_err(on_server(DESTINATION))?;
        }
    }

    Ok(())
}
