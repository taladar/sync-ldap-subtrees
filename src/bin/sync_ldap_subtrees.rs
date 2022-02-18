#![deny(unknown_lints)]
#![deny(renamed_and_removed_lints)]
#![forbid(unsafe_code)]
#![deny(deprecated)]
#![forbid(private_in_public)]
#![forbid(non_fmt_panics)]
#![deny(unreachable_code)]
#![deny(unreachable_patterns)]
#![forbid(unused_doc_comments)]
#![forbid(unused_must_use)]
#![deny(while_true)]
#![deny(unused_parens)]
#![deny(redundant_semicolons)]
#![deny(non_ascii_idents)]
#![deny(confusable_idents)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::cargo_common_metadata)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]
#![deny(clippy::mod_module_files)]
#![doc = include_str!("../../README.md")]

use std::error::Error;

use ldap_types::basic::dn_parser;
use ldap_types::basic::DistinguishedName;
use ldap_types::basic::OIDWithLength;
use ldap_types::filter::search_filter_parser;
use ldap_types::schema::LDAPSchema;
use ldap_utils::{
    connect_with_parameters, delete_recursive, ldap_search, parse_scope, query_ldap_schema,
    query_root_dse, toml_connect_parameters,
};

use lazy_static::lazy_static;

use ldap3::Ldap;

use tracing::instrument;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use serde::{Deserialize, Serialize};

use diff::{Diff, VecDiffType};

use std::collections::{HashMap, HashSet};

use std::iter::FromIterator;

use enum_as_inner::EnumAsInner;

use chumsky::Parser;

use oid::ObjectIdentifier;

use std::convert::TryFrom;

/// Command-line options
#[derive(clap::Parser, Debug)]
#[clap(name = clap::crate_name!(),
       about = clap::crate_description!(),
       author = clap::crate_authors!(),
       version = clap::crate_version!(),
       setting = clap::AppSettings::DeriveDisplayOrder,
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
    #[clap(long, parse(try_from_str = parse_scope), possible_values = [ "base", "one", "sub" ])]
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
    #[clap(long = "attribute", multiple_occurrences = true, number_of_values = 1)]
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

#[tokio::main]
async fn main() {
    FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    match do_sync().await {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    }
}

/// represents an object in the LDAP tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Diff)]
#[diff(attr(#[derive(Debug, Serialize, Deserialize)]))]
struct LDAPEntry {
    /// the DN of the entry
    dn: String,
    /// the textual attributes of the entry
    attrs: HashMap<String, Vec<String>>,
    /// the binary attributes of the entry
    bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// an operation we need to perform to sync the two LDAP servers
#[derive(Debug, Clone, EnumAsInner)]
enum LDAPOperation {
    /// add a new entry
    Add(LDAPEntry),
    /// delete an existing entry
    Delete {
        /// the DN of the entry to delete
        dn: String,
    },
    /// modify attributes of an existing entry
    Modify {
        /// the DN of the entry to modify
        dn: String,
        /// the modifications to textual attributes to perform
        mods: Vec<ldap3::Mod<String>>,
        /// the modifications to binary attributes to perform
        bin_mods: Vec<ldap3::Mod<Vec<u8>>>,
    },
}

impl LDAPOperation {
    /// Used to order operations so parents are added first and children deleted first
    fn operation_apply_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                LDAPOperation::Add(entry1 @ LDAPEntry { .. }),
                LDAPOperation::Add(entry2 @ LDAPEntry { .. }),
            ) => {
                let parsed_dn1: Result<DistinguishedName, _> =
                    dn_parser().parse(entry1.dn.to_owned());
                let parsed_dn2: Result<DistinguishedName, _> =
                    dn_parser().parse(entry2.dn.to_owned());
                if let (Ok(parsed_dn1), Ok(parsed_dn2)) = (parsed_dn1, parsed_dn2) {
                    Some(parsed_dn1.cmp(&parsed_dn2))
                } else {
                    None
                }
            }
            (op1 @ LDAPOperation::Delete { .. }, op2 @ LDAPOperation::Delete { .. }) => {
                let parsed_dn1: Result<DistinguishedName, _> =
                    dn_parser().parse(op1.as_delete().unwrap().to_owned());
                let parsed_dn2: Result<DistinguishedName, _> =
                    dn_parser().parse(op2.as_delete().unwrap().to_owned());
                if let (Ok(parsed_dn1), Ok(parsed_dn2)) = (parsed_dn1, parsed_dn2) {
                    Some(parsed_dn1.cmp(&parsed_dn2))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// transform textual modifications to binary modifications so they can both be applied as part
/// of the same modify operation because otherwise we might successfully apply the textual modifications
/// and then fail on the binary ones, leaving behind a half-modified object
fn mods_as_bin_mods<'a, T>(mods: T) -> Vec<ldap3::Mod<Vec<u8>>>
where
    T: IntoIterator<Item = &'a ldap3::Mod<String>>,
{
    let mut result: Vec<ldap3::Mod<Vec<u8>>> = vec![];
    for m in mods {
        match m {
            ldap3::Mod::Add(k, v) => {
                result.push(ldap3::Mod::Add(
                    k.as_bytes().to_vec(),
                    v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                ));
            }
            ldap3::Mod::Delete(k, v) => {
                result.push(ldap3::Mod::Delete(
                    k.as_bytes().to_vec(),
                    v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                ));
            }
            ldap3::Mod::Replace(k, v) => {
                result.push(ldap3::Mod::Replace(
                    k.as_bytes().to_vec(),
                    v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                ));
            }
            ldap3::Mod::Increment(k, v) => {
                result.push(ldap3::Mod::Increment(
                    k.as_bytes().to_vec(),
                    v.as_bytes().to_vec(),
                ));
            }
        }
    }
    result
}

#[instrument(skip(ldap, ldap_operations))]
async fn apply_ldap_operations(
    ldap: &mut Ldap,
    ldap_base_dn: &str,
    ldap_operations: &[LDAPOperation],
    controls: Vec<ldap3::controls::RawControl>,
) -> Result<(), Box<dyn Error>> {
    tracing::debug!(
        "The following operations use the LDAP controls: {:#?}",
        controls
    );
    for op in ldap_operations {
        match op {
            LDAPOperation::Add(LDAPEntry {
                dn,
                attrs,
                bin_attrs,
            }) => {
                let full_dn = format!("{},{}", dn, ldap_base_dn);
                tracing::debug!(
                    "Adding LDAP entry at {} with attributes\n{:#?}\nand binary attributes\n{:#?}",
                    &full_dn,
                    attrs,
                    bin_attrs
                );
                // we need to perform the add in one operation or we will run into problems with
                // objectclass requirements
                let mut combined_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = bin_attrs
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.to_owned().as_bytes().to_vec(),
                            v.iter().map(|s| s.to_owned()).collect::<HashSet<Vec<u8>>>(),
                        )
                    })
                    .collect();
                combined_attrs.extend(attrs.iter().map(|(k, v)| {
                    (
                        k.to_owned().as_bytes().to_vec(),
                        v.iter()
                            .map(|s| s.as_bytes().to_vec())
                            .collect::<HashSet<Vec<u8>>>(),
                    )
                }));
                ldap.with_controls(controls.to_owned())
                    .add(&full_dn, combined_attrs)
                    .await?
                    .success()?;
            }
            LDAPOperation::Delete { dn } => {
                let full_dn = format!("{},{}", dn, ldap_base_dn);
                tracing::debug!("Deleting LDAP entry at {}", &full_dn);
                delete_recursive(ldap, &full_dn, controls.to_owned()).await?;
            }
            LDAPOperation::Modify { dn, mods, bin_mods } => {
                let full_dn = format!("{},{}", dn, ldap_base_dn);
                tracing::debug!("Modifying LDAP entry at {} with modifications\n{:#?}\nand binary modifications\n{:#?}", &full_dn, mods, bin_mods);
                let mut combined_mods = bin_mods.to_owned();
                combined_mods.extend(mods_as_bin_mods(mods));
                ldap.with_controls(controls.to_owned())
                    .modify(&full_dn, combined_mods.to_vec())
                    .await?
                    .success()?;
            }
        }
    }

    Ok(())
}

#[instrument(skip(ldap, entries))]
async fn search_entries(
    ldap: &mut Ldap,
    base_dn: &str,
    search_base: &str,
    scope: ldap3::Scope,
    filter: &str,
    attrs: &[String],
    entries: &mut HashMap<String, LDAPEntry>,
) -> Result<(), Box<dyn Error>> {
    let it = ldap_search(
        ldap,
        &format!("{},{}", search_base, base_dn),
        scope,
        filter,
        attrs.to_owned(),
    )
    .await?;
    for entry in it {
        tracing::debug!("Found entry {}", entry.dn);
        if let Some(s) = entry.dn.strip_suffix(&format!(",{}", &base_dn)) {
            entries.insert(
                s.to_string(),
                LDAPEntry {
                    dn: s.to_string(),
                    attrs: entry.attrs,
                    bin_attrs: entry.bin_attrs,
                },
            );
        } else {
            tracing::error!(
                "Failed to remove base dn {} from entry DN {}",
                base_dn,
                entry.dn
            );
        }
    }
    Ok(())
}

#[instrument(skip(
    source_entry,
    source_ldap_schema,
    source_base_dn,
    destination_entry,
    destination_base_dn,
    options
))]
fn mod_value(
    attr_name: &str,
    source_entry: &LDAPEntry,
    source_ldap_schema: &LDAPSchema,
    source_base_dn: &str,
    destination_entry: Option<&LDAPEntry>,
    destination_base_dn: &str,
    options: &Options,
) -> Result<Option<ldap3::Mod<String>>, Box<dyn Error>> {
    lazy_static! {
        static ref DN_SYNTAX_OID: OIDWithLength = OIDWithLength {
            oid: ObjectIdentifier::try_from("1.3.6.1.4.1.1466.115.121.1.12").unwrap(),
            length: None
        };
    }
    if let Some(values) = source_entry.attrs.get(attr_name) {
        let mut replacement_values = HashSet::from_iter(values.iter().cloned());
        if attr_name == "objectClass" {
            for io in &options.ignore_object_classes {
                replacement_values.remove(io);
            }
        }
        let attr_type_syntax =
            source_ldap_schema.find_attribute_type_property(attr_name, |at| at.syntax.as_ref());
        tracing::debug!(
            "Attribute type syntax for altered attribute {}: {:#?}",
            attr_name,
            attr_type_syntax
        );
        if let Some(syntax) = attr_type_syntax {
            if DN_SYNTAX_OID.eq(syntax) {
                tracing::debug!(
                    "Replacing base DN {} with base DN {}",
                    source_base_dn,
                    destination_base_dn
                );
                replacement_values = replacement_values
                    .into_iter()
                    .map(|s| s.replace(source_base_dn, destination_base_dn))
                    .collect();
            }
        }
        if let Some(destination_entry) = destination_entry {
            if let Some(destination_values) = destination_entry.attrs.get(attr_name) {
                let mut replacement_values_sorted: Vec<String> =
                    replacement_values.iter().cloned().collect();
                replacement_values_sorted.sort();
                let mut destination_values: Vec<String> = destination_values.to_vec();
                destination_values.sort();
                tracing::debug!("Checking if replacement values and destination values are identical (case sensitive):\n{:#?}\n{:#?}", destination_values, replacement_values_sorted);
                if replacement_values_sorted == destination_values {
                    tracing::debug!("Skipping attribute {} because replacement values and destination values are identical (case sensitive)", attr_name);
                    return Ok(None);
                }
                let attr_type_equality = source_ldap_schema
                    .find_attribute_type_property(attr_name, |at| at.equality.as_ref());
                tracing::debug!(
                    "Attribute type equality for altered attribute {}: {:#?}",
                    attr_name,
                    attr_type_equality
                );
                if let Some(equality) = &attr_type_equality {
                    if equality.describes_case_insensitive_match() {
                        let mut lower_destination_values: Vec<String> = destination_values
                            .iter()
                            .map(|s| s.to_lowercase())
                            .collect();
                        lower_destination_values.sort();
                        let mut lower_replacement_values: Vec<String> = replacement_values
                            .iter()
                            .map(|s| s.to_lowercase())
                            .collect();
                        lower_replacement_values.sort();
                        tracing::debug!("Checking if replacement values and destination values are identical (case insensitive):\n{:#?}\n{:#?}", lower_destination_values, lower_replacement_values);
                        if lower_destination_values == lower_replacement_values {
                            tracing::debug!("Skipping attribute {} because replacement values and destination values are identical (case insensitive)", attr_name);
                            return Ok(None);
                        }
                    }
                }
            }
        }
        Ok(Some(ldap3::Mod::Replace(
            attr_name.to_string(),
            replacement_values,
        )))
    } else {
        Ok(Some(ldap3::Mod::Delete(
            attr_name.to_string(),
            HashSet::new(),
        )))
    }
}

#[instrument]
async fn do_sync() -> Result<(), Box<dyn Error>> {
    let options = <Options as clap::Parser>::try_parse()?;
    tracing::debug!("{:#?}", options);

    lazy_static! {
        static ref DN_SYNTAX_OID: OIDWithLength = OIDWithLength {
            oid: ObjectIdentifier::try_from("1.3.6.1.4.1.1466.115.121.1.12").unwrap(),
            length: None
        };
    }

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
        .expect("No source schema");
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
        .expect("No destination schema");
    tracing::debug!("Destination LDAP schema {:#?}", destination_ldap_schema);

    let source_search_filter = search_filter_parser()
        .parse(options.search_filter.clone())
        .expect("Failed to parse search filter");
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

    let diff = Diff::diff(&source_entries, &destination_entries);
    tracing::debug!("Diff:\n{:#?}", diff);
    let mut ldap_operations: Vec<LDAPOperation> = vec![];
    for (altered_dn, change) in diff.altered {
        tracing::debug!("Processing altered DN {}", altered_dn);
        let source_entry: Option<&LDAPEntry> = source_entries.get(&altered_dn);
        let destination_entry: Option<&LDAPEntry> = destination_entries.get(&altered_dn);
        if let Some(source_entry) = source_entry {
            let mut ldap_mods: Vec<ldap3::Mod<String>> = vec![];
            let mut ldap_bin_mods: Vec<ldap3::Mod<Vec<u8>>> = vec![];
            for (attr_name, attr_value_changes) in &change.attrs.altered {
                if options.ignore_attributes.contains(attr_name) {
                    continue;
                }
                for attr_value_change in &attr_value_changes.0 {
                    match attr_value_change {
                        VecDiffType::Removed { .. }
                        | VecDiffType::Inserted { .. }
                        | VecDiffType::Altered { .. } => {
                            let m = mod_value(
                                attr_name,
                                source_entry,
                                &source_ldap_schema,
                                &source_base_dn,
                                destination_entry,
                                &destination_base_dn,
                                &options,
                            )?;
                            if let Some(m) = m {
                                if !ldap_mods.contains(&m) {
                                    ldap_mods.push(m);
                                }
                            }
                        }
                    }
                }
            }
            for attr_name in &change.attrs.removed {
                if options.ignore_attributes.contains(attr_name) {
                    continue;
                }
                let mut replacement_values =
                    HashSet::from_iter(source_entry.attrs[attr_name].iter().cloned());
                if attr_name == "objectClass" {
                    for io in &options.ignore_object_classes {
                        replacement_values.remove(io);
                    }
                }
                let attr_type_syntax = source_ldap_schema
                    .find_attribute_type_property(attr_name, |at| at.syntax.as_ref());
                tracing::debug!(
                    "Attribute type syntax for deleted attribute {}: {:#?}",
                    attr_name,
                    attr_type_syntax
                );
                if let Some(syntax) = attr_type_syntax {
                    if DN_SYNTAX_OID.eq(syntax) {
                        tracing::debug!(
                            "Replacing base DN {} with base DN {}",
                            source_base_dn,
                            destination_base_dn
                        );
                        replacement_values = replacement_values
                            .into_iter()
                            .map(|s| s.replace(&source_base_dn, &destination_base_dn))
                            .collect();
                    }
                }
                ldap_mods.push(ldap3::Mod::Add(attr_name.to_string(), replacement_values));
            }
            for (attr_name, attr_value_changes) in &change.bin_attrs.altered {
                if options.ignore_attributes.contains(attr_name) {
                    continue;
                }
                for attr_value_change in &attr_value_changes.0 {
                    match attr_value_change {
                        VecDiffType::Removed { .. }
                        | VecDiffType::Inserted { .. }
                        | VecDiffType::Altered { .. } => {
                            if let Some(values) = source_entry.bin_attrs.get(attr_name) {
                                let replace_mod = ldap3::Mod::Replace(
                                    attr_name.as_bytes().to_vec(),
                                    HashSet::from_iter(values.iter().cloned()),
                                );
                                if !ldap_bin_mods.contains(&replace_mod) {
                                    ldap_bin_mods.push(replace_mod)
                                }
                            } else {
                                ldap_bin_mods.push(ldap3::Mod::Delete(
                                    attr_name.as_bytes().to_vec(),
                                    HashSet::new(),
                                ));
                            }
                        }
                    }
                }
            }
            for attr_name in &change.bin_attrs.removed {
                if options.ignore_attributes.contains(attr_name) {
                    continue;
                }
                ldap_bin_mods.push(ldap3::Mod::Add(
                    attr_name.as_bytes().to_vec(),
                    HashSet::from_iter(source_entry.bin_attrs[attr_name].iter().cloned()),
                ));
            }
            if options.update && !(ldap_mods.is_empty() && ldap_bin_mods.is_empty()) {
                ldap_operations.push(LDAPOperation::Modify {
                    dn: source_entry.dn.clone(),
                    mods: ldap_mods,
                    bin_mods: ldap_bin_mods,
                });
            }
        } else if options.delete {
            ldap_operations.push(LDAPOperation::Delete {
                dn: altered_dn.clone(),
            });
        }
    }
    for removed_dn in diff.removed {
        if options.add {
            let mut new_entry = source_entries[&removed_dn].clone();
            for ia in &options.ignore_attributes {
                new_entry.attrs.remove(ia);
                new_entry.bin_attrs.remove(ia);
            }
            if let Some((k, v)) = new_entry.attrs.remove_entry("objectClass") {
                let ioc = &options.ignore_object_classes;
                let new_v = v.into_iter().filter(|x| !ioc.contains(x)).collect();
                new_entry.attrs.insert(k, new_v);
            }
            for (attr_name, attr_values) in new_entry.attrs.iter_mut() {
                let attr_type_syntax = source_ldap_schema
                    .find_attribute_type_property(attr_name, |at| at.syntax.as_ref());
                tracing::debug!(
                    "Attribute type syntax for attribute {} in deleted entry {}: {:#?}",
                    attr_name,
                    removed_dn,
                    attr_type_syntax
                );
                if let Some(syntax) = attr_type_syntax {
                    if DN_SYNTAX_OID.eq(syntax) {
                        tracing::debug!(
                            "Replacing base DN {} with base DN {}",
                            source_base_dn,
                            destination_base_dn
                        );
                        for s in attr_values.iter_mut() {
                            *s = s.replace(&source_base_dn, &destination_base_dn);
                        }
                    }
                }
            }
            ldap_operations.push(LDAPOperation::Add(new_entry));
        }
    }
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

    ldap_operations.sort_by(|a, b| {
        a.operation_apply_cmp(b)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

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
