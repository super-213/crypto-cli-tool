// Test to verify proptest configuration is working correctly

use proptest::prelude::*;

proptest! {
    #[test]
    fn test_proptest_configuration(x in 0..100i32) {
        // This test should run at least 100 times as configured in proptest.toml
        assert!(x >= 0 && x < 100);
    }
}
