//! Safe defaults for page-based pagination. Call validated() before querying.

use super::api_errors::ApiError;
use serde::Deserialize;

const MAX_PER_PAGE: u32 = 100;

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Pagination {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

const fn default_page() -> u32 {
    1
}

const fn default_per_page() -> u32 {
    20
}

impl Pagination {
    pub fn validated(self) -> Result<Self, ApiError> {
        if self.page == 0 || self.per_page == 0 || self.per_page > MAX_PER_PAGE {
            return Err(ApiError::bad_request("Invalid pagination parameters"));
        }
        Ok(self)
    }

    pub fn limit(self) -> i64 {
        i64::from(self.per_page)
    }

    pub fn offset(self) -> i64 {
        (i64::from(self.page) - 1) * i64::from(self.per_page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_and_oversized_pagination() {
        for (page, per_page) in [(0, 20), (1, 0), (1, 101)] {
            assert!(Pagination { page, per_page }.validated().is_err());
        }
    }

    #[test]
    fn computes_database_offset_without_overflow() {
        let pagination = Pagination {
            page: u32::MAX,
            per_page: MAX_PER_PAGE,
        }
        .validated()
        .expect("valid");
        assert_eq!(
            pagination.offset(),
            (i64::from(u32::MAX) - 1) * i64::from(MAX_PER_PAGE)
        );
    }
}
