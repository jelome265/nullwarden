use governor::middleware::StateInformationMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;

pub fn get_auth_rate_limit_layer(
    requests: u32,
) -> GovernorLayer<'static, PeerIpKeyExtractor, StateInformationMiddleware> {
    let config = Box::leak(Box::new(
        GovernorConfigBuilder::default()
            .per_second(requests as u64)
            .burst_size(requests)
            .use_headers() // This switches to StateInformationMiddleware
            .finish()
            .unwrap(),
    ));

    GovernorLayer { config }
}
