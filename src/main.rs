use std::net::{Ipv6Addr, SocketAddr};
use hyper::{body::Bytes, header::{CONTENT_TYPE, self}, HeaderMap};
// use reverse_proxy_service::Identity;
use reqwest::Client;
use chrono::Utc;

use axum::{
    body::{Body, HttpBody},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};

use tower::ServiceBuilder;
use tower_http::{request_id::MakeRequestUuid, trace::TraceLayer, ServiceBuilderExt};
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use uuid::Uuid;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer().with_ansi(false))
        .init();

    let svc = ServiceBuilder::new()
        .set_x_request_id(MakeRequestUuid)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("unknown");
                tracing::info_span!("req", id = request_id)
            }),
        )
        .propagate_x_request_id();

    let app = Router::new()
        .route("/*rest", axum::routing::any(reverse_proxy_vault))
        .layer(middleware::from_fn(log_request_response))
        .layer(svc);

    let listening_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8080));
    tracing::info!("Server listening on {listening_addr}");

    axum::Server::bind(&listening_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn reverse_proxy_vault(req: Request<axum::body::Body>) -> impl IntoResponse {
    let uuid = Uuid::new_v4();
    let timestamp = Utc::now().timestamp().to_string();
    let file = format!("{timestamp}-{uuid}.log");
    let (parts, mut body) = req.into_parts();
    let client = Client::new();
    
    let mm_url = parts.uri.path_and_query().map(|path| path.as_str()).unwrap_or_else(|| parts.uri.path());
    tracing::info!("========================================== {mm_url}");
    let method = parts.method.clone();
    let headers = parts.headers.clone();
    let uri = parts.uri.clone();

    let body = body.data().await.unwrap().unwrap().to_vec();
    let request_body = String::from_utf8(body.clone()).unwrap();

    let response = client.put(format!("https://vault.patr.app{mm_url}"))
        .headers(parts.headers.into_iter().filter_map(|(key, value)| {
            let key = key.unwrap();
            if key.as_str() != "X-Forwarded-For"  {
                Some((key, value))
            } else {
                None
            }
        }).collect::<HeaderMap>())
        .body(body.clone())
        .send()
        .await.unwrap();

    // let response = client.put(format!("https://vault.patr.app{mm_url}"))
    //     .header("X-Vault-Token", "hvs.yiepYrNXBQaTWWPFN33UnxLQ")
    //     .header(header::HOST, "vault.patr.app")
    //     .header(header::USER_AGENT, "Go-http-client/2.0")
    //     .header(header::CONTENT_LENGTH, "1066")
    //     .header(header::ACCEPT_ENCODING, "gzip")
    //     // .body(body.clone())
    //     .send()
    //     .await.unwrap();

    let request_header = headers.iter().map(|(key, value)| {
        let value = value.to_str().unwrap();
        format!("{key}: {value}")
    }).collect::<Vec<_>>().join("\n");

    let request_string = format!(
        r#"{} {}
        {}
        {}"#,
        method,
        uri.path_and_query().unwrap().as_str(),
        request_header,
        request_body
    );

    let response_header = response.headers().iter().map(|(key, value)| {
        let value = value.to_str().unwrap();
        format!("{key}: {value}")
    }).collect::<Vec<_>>().join("\n");

    let status = response.status().clone();
    let byte = response.bytes().await.unwrap();
    let response_body = std::str::from_utf8(&byte).unwrap(); 

    let response_string =  format!(
        r#"{}
        {}
        {}"#,
        status,
        response_header,
        response_body
    );
    tokio::fs::write(file, format!(
        "
        {}
        ====================================================================================
        {}
        ",
        request_string,
        response_string
    )).await.unwrap();

}

async fn log_request_response(
    req: Request<axum::body::Body>,
    next: Next<axum::body::Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!(
        "{} {}",
        req.method().as_str(),
        req.uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or_else(|| req.uri().path())
    );
    let (req_parts, req_body) = req.into_parts();
    let bytes = buffer_and_print("request", &req_parts.headers, req_body).await?;
    let req = Request::from_parts(req_parts, Body::from(bytes));
    let res = next.run(req).await;
    let (mut res_parts, res_body) = res.into_parts();
    let bytes = buffer_and_print("response", &res_parts.headers, res_body).await?;
    // When your encoding is chunked there can be problems without removing the header
    res_parts.headers.remove("transfer-encoding");
    let res = Response::from_parts(res_parts, Body::from(bytes));

    Ok(res)
}

async fn buffer_and_print<B>(
    meta_desc: &str,
    headers: &HeaderMap,
    body: B,
) -> Result<Bytes, (StatusCode, String)>
where
    B: HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let is_json_body = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map_or(false, |value| value == "application/json");

    let headers = headers
        .iter()
        .map(|(name, value)| (name.as_str().into(), value.to_str().unwrap_or("").into()))
        .collect::<serde_json::Map<_, _>>();

    let headers = serde_json::to_string_pretty(&headers)
        .unwrap_or_else(|err| format!("Error while parsing header: {err}"));

    tracing::info!("{meta_desc} headers: {headers}");
    let bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::info!("{meta_desc} Error while parsing body: {err}");
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {} body: {}", meta_desc, err),
            ));
        }
    };

    if let Ok(body) = std::str::from_utf8(&bytes) {
        if is_json_body {
            if let Ok(body) = serde_json::from_str::<serde_json::Value>(body) {
                let body = serde_json::to_string_pretty(&body)
                .unwrap_or_else(|err| format!("Error while parsing body: {err}"));
                tracing::info!("{meta_desc} body: \n{body}");
                return Ok(bytes);
            }
        }

        tracing::info!("{meta_desc} body: \n{body}");
    }

    Ok(bytes)
}