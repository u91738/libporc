#include <algorithm>
#include <cinttypes>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <iterator>
#include <optional>
#include <vector>

#pragma once

namespace porc::stats {

uintmax_t mean(const std::vector<int64_t> &v);

uintmax_t median(const std::vector<int64_t> &v);

uintmax_t median(std::vector<int64_t> &&v);

long double covariance(const std::vector<int64_t> a, const std::vector<int64_t> &b);

long double standard_deviation(const std::vector<int64_t> &a);

long double standard_deviation(const std::vector<int64_t> &a, const std::vector<int64_t> &b);

long double corrcoef(const std::vector<int64_t> &a, const std::vector<int64_t> &b);

/*
    Distribution of values to a set of N-buckets of equal size between min and max
    i.e. if value 11 is found 123 times and value 12 is found 45 times,
    bucket that covers values [10 .. 15) will have a value 123 + 45 = 168.
    Values outside of [min .. max] will land into first and last bucket accordingly.
    Any comparison of two distributions only make sense
    for distributions with the same min, max and bucket_count
*/
class bucket_distribution {
    private:
        int64_t _min = 0;
        int64_t _max = 0;
        int64_t _bucket_step = 0;
        std::vector<int64_t> _buckets;
    public:
        bucket_distribution() {}
        bucket_distribution(int64_t min, int64_t max, size_t bucket_count, const std::vector<int64_t> &values);

        size_t bucket_index(int64_t v) const;

        const int64_t get_min() const { return this->_min; }
        const int64_t get_max() const { return this->_max; }
        const std::vector<int64_t> & buckets() const { return this->_buckets; }

        long double corrcoef(bucket_distribution& d);
};

}
