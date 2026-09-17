use crate::core::app_config::get_app_config;
use crate::core::command::{AuthConfig, Command};
use crate::core::config::Config;
use crate::core::env::get_env;
use crate::core::ephenv::get_ephenvs;
use crate::utils::error::CliError;
use crate::utils::http::handle_request;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use edit::edit;
use handlebars::Handlebars;
use hmac::{Hmac, Mac};
use regex::{NoExpand, Regex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const BREAKING_CHANGE_VERSION: &str = "0.6.0";

handlebars::handlebars_helper!(base64_helper: |value: str| STANDARD.encode(value));
handlebars::handlebars_helper!(basic_auth_helper: |username: str, password: str| {
    format!("Basic {}", STANDARD.encode(format!("{}:{}", username, password)))
});
handlebars::handlebars_helper!(url_encode_helper: |value: str| urlencoding::encode(value).into_owned());

fn template_engine() -> Handlebars<'static> {
    let mut handlebars = Handlebars::new();
    handlebars.register_escape_fn(handlebars::no_escape);
    handlebars.register_helper("base64", Box::new(base64_helper));
    handlebars.register_helper("basicAuth", Box::new(basic_auth_helper));
    handlebars.register_helper("urlEncode", Box::new(url_encode_helper));
    handlebars
}

fn required_env<'a>(
    data: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, Box<dyn Error>> {
    data.get(name).map(String::as_str).ok_or_else(|| {
        Box::new(CliError {
            message: format!("required environment variable '{}' is not set", name),
        }) as Box<dyn Error>
    })
}

fn hmac_sha256(secret: &str, value: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn request_path(url: &reqwest::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    }
}

fn agency_signature(secret: &str, url: &str, timestamp: u64, body: Option<&str>) -> String {
    let mut payload = format!("{}\n{}", url, timestamp);
    if let Some(body) = body {
        payload.push('\n');
        payload.push_str(body);
    }
    STANDARD.encode(hmac_sha256(secret, &payload))
}

fn cash_app_signature(
    secret: &str,
    method: &str,
    path: &str,
    host: &str,
    authorization: &str,
    body: Option<&str>,
) -> String {
    let body_digest = Sha256::digest(body.unwrap_or_default().as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    let signed_headers = format!(
        "accept:application/json\nauthorization:{}\ncontent-type:application/json\nhost:{}",
        authorization, host
    );
    let payload = format!("{}\n{}\n{}\n{}", method, path, signed_headers, body_digest);
    hmac_sha256(secret, &payload)
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn apply_auth(
    auth: &AuthConfig,
    method: &str,
    url: &reqwest::Url,
    body: Option<&str>,
    headers: &mut HashMap<String, String>,
    env: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    match auth {
        AuthConfig::Agency {
            api_key_env,
            secret_env,
        } => {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let signature = agency_signature(
                required_env(env, secret_env)?,
                url.as_str(),
                timestamp,
                body,
            );
            headers.insert(
                "X-Afterpay-Request-ApiKey".to_string(),
                required_env(env, api_key_env)?.to_string(),
            );
            headers.insert("X-Afterpay-Request-Date".to_string(), timestamp.to_string());
            headers.insert("X-Afterpay-Request-Signature".to_string(), signature);
        }
        AuthConfig::CashApp {
            client_id_env,
            api_key_env,
            api_secret_env,
            region_env,
        } => {
            let client_id = required_env(env, client_id_env)?;
            let api_key = required_env(env, api_key_env)?;
            let authorization = format!("Client {} {}", client_id, api_key);
            let host = match url.port() {
                Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
                None => url.host_str().unwrap_or_default().to_string(),
            };
            let signature = match env.get(api_secret_env) {
                Some(secret) => format!(
                    "V1 {}",
                    cash_app_signature(
                        secret,
                        method,
                        &request_path(url),
                        &host,
                        &authorization,
                        body,
                    )
                ),
                None if host.starts_with("sandbox.") => env
                    .get("CASH_X_SIGNATURE")
                    .cloned()
                    .unwrap_or_else(|| "sandbox:skip-signature-check".to_string()),
                None => {
                    return Err(Box::new(CliError {
                        message: format!(
                            "required environment variable '{}' is not set",
                            api_secret_env
                        ),
                    }))
                }
            };

            headers.insert("Accept".to_string(), "application/json".to_string());
            headers.insert("Authorization".to_string(), authorization);
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert(
                "X-Region".to_string(),
                env.get(region_env)
                    .cloned()
                    .unwrap_or_else(|| "SEA".to_string()),
            );
            headers.insert("X-Signature".to_string(), signature);
        }
    }
    Ok(())
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn signs_agency_requests() {
        assert_eq!(
            agency_signature(
                "secret",
                "https://agencyapi.sandbox.afterpay.com/v1/test?x=1",
                1_706_263_066,
                Some(r#"{"a":1}"#)
            ),
            "557jEBlpa1abEP9GAzg0tRRjITBEWcJJnj72Y97/JVk="
        );
    }

    #[test]
    fn signs_cash_app_requests() {
        assert_eq!(
            cash_app_signature(
                "secret",
                "GET",
                "/network/v1/payments?limit=50",
                "sandbox.api.cash.app",
                "Client client key",
                None,
            ),
            "fd317ed78e87829961fde4f0dea180b8ddb6e850341ca9b0adc2643cbf74d633"
        );
    }
}

fn check_upgrade_notice() -> bool {
    let mut app_config = get_app_config();
    let needs_notice = match app_config.get_last_seen_version() {
        Some(version) => version.as_str() < BREAKING_CHANGE_VERSION,
        None => true,
    };

    if needs_notice {
        eprintln!(
            "NOTE: As of v{}, the editor no longer opens automatically for request bodies.",
            BREAKING_CHANGE_VERSION
        );
        eprintln!("Use --edit-body (-e) to review/edit the body before sending.");
        eprintln!("Please re-run your command to continue.");
        app_config.set_last_seen_version(env!("CARGO_PKG_VERSION").to_string());
    }

    needs_notice
}

fn replace_params(input: String, params: &HashMap<String, String>) -> String {
    params.keys().fold(input, |acc, x| {
        acc.replace(&format!(":{}", x), params.get(x).unwrap())
    })
}

fn split_option<'a>(
    value: &'a str,
    separator: char,
    format: &str,
) -> Result<(&'a str, &'a str), Box<dyn Error>> {
    value.split_once(separator).ok_or_else(|| {
        Box::new(CliError {
            message: format!("invalid '{}'; expected {}", value, format),
        }) as Box<dyn Error>
    })
}

pub struct RunOptions {
    pub edit_body: bool,
    pub body_file: Option<PathBuf>,
    pub json_output: bool,
    pub query: Vec<String>,
    pub headers: Vec<String>,
}

struct TypedSubstitutionResult {
    body: String,
    file_fields: HashMap<String, PathBuf>,
}

fn replace_params_typed(
    input: String,
    params: &HashMap<String, String>,
    param_types: &HashMap<String, Option<String>>,
) -> Result<TypedSubstitutionResult, Box<dyn Error>> {
    let mut result = input.clone();
    let mut file_fields: HashMap<String, PathBuf> = HashMap::new();

    for (param_name, param_value) in params {
        let param_type = param_types
            .get(param_name.as_str())
            .and_then(|t| t.as_deref());

        match param_type {
            Some("boolean") => {
                if param_value != "true" && param_value != "false" {
                    return Err(Box::new(CliError {
                        message: format!(
                            "Parameter '{}' expects a boolean value (true/false), got '{}'",
                            param_name, param_value
                        ),
                    }));
                }
                let placeholder = Regex::new(&format!(
                    r#"":{}\|boolean(?:=[^"]*)?""#,
                    regex::escape(param_name)
                ))?;
                result = placeholder
                    .replace_all(&result, NoExpand(param_value))
                    .into_owned();
            }
            Some("number") => {
                if param_value.parse::<f64>().is_err() {
                    return Err(Box::new(CliError {
                        message: format!(
                            "Parameter '{}' expects a number value, got '{}'",
                            param_name, param_value
                        ),
                    }));
                }
                let placeholder = Regex::new(&format!(
                    r#"":{}\|number(?:=[^"]*)?""#,
                    regex::escape(param_name)
                ))?;
                result = placeholder
                    .replace_all(&result, NoExpand(param_value))
                    .into_owned();
            }
            Some("file") => {
                let path = PathBuf::from(param_value);
                if !path.exists() {
                    return Err(Box::new(CliError {
                        message: format!(
                            "File not found for parameter '{}': {}",
                            param_name, param_value
                        ),
                    }));
                }

                let placeholder = format!(":{}|file", param_name);
                if let Ok(mut json_val) = serde_json::from_str::<Value>(&result) {
                    if let Some(obj) = json_val.as_object_mut() {
                        let mut file_key = None;
                        for (key, val) in obj.iter() {
                            if let Some(s) = val.as_str() {
                                if s == placeholder || s.starts_with(&format!("{}=", placeholder)) {
                                    file_key = Some(key.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(key) = file_key {
                            let key_clone = key.clone();
                            obj.remove(&key);
                            result = serde_json::to_string(&json_val).unwrap();
                            file_fields.insert(key_clone, path);
                        }
                    }
                }
            }
            _ => {
                let placeholder = Regex::new(&format!(
                    r#":{}\b(?:\|\w+)?(?:=[^"]*)?"#,
                    regex::escape(param_name)
                ))?;
                result = placeholder
                    .replace_all(&result, NoExpand(param_value))
                    .into_owned();
            }
        }
    }

    Ok(TypedSubstitutionResult {
        body: result,
        file_fields,
    })
}

pub async fn run(
    api_call: &Command,
    param_values: HashMap<String, String>,
    options: RunOptions,
) -> Result<(), Box<dyn Error>> {
    if check_upgrade_notice() {
        return Ok(());
    }

    let config = Config::new();
    let hb_handle = template_engine();

    let url = api_call.url.as_str();

    let current_env = match get_env() {
        Some(e) => e,
        None => {
            return Err(Box::new(CliError {
                message: "env not set".to_string(),
            }))
        }
    };
    let env_data = match config.envs.get(&current_env) {
        Some(d) => d,
        None => {
            return Err(Box::new(CliError {
                message: "env not recognized".to_string(),
            }))
        }
    };
    let ephenv_data = get_ephenvs();
    let merged_data = env_data
        .clone()
        .into_iter()
        .chain(ephenv_data.clone())
        .chain(std::env::vars())
        .collect::<HashMap<String, String>>();

    let url_with_env_vars = hb_handle.render_template(url, &merged_data)?;

    let url_to_call = replace_params(url_with_env_vars, &param_values);

    let (input, file_fields) = if let Some(ref body_file_path) = options.body_file {
        let file_content = std::fs::read_to_string(body_file_path).map_err(|e| {
            Box::new(CliError {
                message: format!(
                    "Failed to read body file '{}': {}",
                    body_file_path.display(),
                    e
                ),
            })
        })?;
        let rendered = hb_handle.render_template(&file_content, &merged_data)?;
        (Some(rendered), None)
    } else if api_call.body.is_some() {
        let serialized = serde_json::to_string_pretty(&api_call.body).unwrap();
        let rendered = hb_handle.render_template(&serialized, &merged_data)?;

        let param_types = api_call.body_param_types();
        let typed_result = replace_params_typed(rendered, &param_values, &param_types)?;

        let body_str = if options.edit_body {
            edit(&typed_result.body).expect("Unable to open system editor")
        } else {
            typed_result.body
        };

        let file_fields = if typed_result.file_fields.is_empty() {
            None
        } else {
            Some(typed_result.file_fields)
        };

        (Some(body_str), file_fields)
    } else {
        (None, None)
    };

    let mut url_to_call = reqwest::Url::parse(&url_to_call)?;
    for query in &options.query {
        let (name, value) = split_option(query, '=', "NAME=VALUE")?;
        url_to_call.query_pairs_mut().append_pair(name, value);
    }

    let mut headers = api_call
        .headers
        .clone()
        .into_iter()
        .map(|(k, v)| hb_handle.render_template(&v, &merged_data).map(|v| (k, v)))
        .collect::<Result<HashMap<String, String>, _>>()?;
    for header in &options.headers {
        let (name, value) = split_option(header, ':', "NAME:VALUE")?;
        headers.insert(name.trim().to_string(), value.trim().to_string());
    }
    if let Some(auth) = &api_call.auth {
        apply_auth(
            auth,
            &api_call.method.to_string(),
            &url_to_call,
            input.as_deref(),
            &mut headers,
            &merged_data,
        )?;
    }

    let response = handle_request(
        url_to_call.to_string(),
        &api_call.method,
        &headers,
        input,
        file_fields,
    )
    .await?;

    get_app_config().set_prev_request(response.clone());

    if options.json_output {
        println!("{}", serde_json::to_string(&response).unwrap());
    } else {
        let response_json_result = serde_json::from_str::<Value>(response.clone().body.as_str());

        match response_json_result {
            Ok(response_json) => {
                let mut out = stdout();
                colored_json::write_colored_json(&response_json, &mut out).unwrap();
                out.flush().unwrap();
                writeln!(out).unwrap();
            }
            Err(_error) => {
                println!("{}", response.body);
            }
        };
    }

    let mut postscript_env_vars = merged_data.clone();
    postscript_env_vars.extend(param_values);

    api_call
        .run_post_command_script(
            &serde_json::to_string_pretty(&response.clone()).unwrap(),
            &postscript_env_vars,
        )
        .unwrap();

    Ok(())
}
