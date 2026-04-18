use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use std::sync::Arc;

pub fn get_auth_rate_limit_layer(requests: u32) -> GovernorLayer {
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(requests as u64)
            .burst_size(requests)
            .finish()
            .unwrap(),
    );

    GovernorLayer { config }
}
