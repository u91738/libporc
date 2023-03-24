#include <cassert>
#include <cmath>
#include "porc/stats.hpp"

namespace porc::stats {

uintmax_t mean(const std::vector<int64_t> &v)
{
    assert(!v.empty());
    uintmax_t r = 0;
    for (auto i : v)
        r += i;
    return r / v.size();
}

uintmax_t median(std::vector<int64_t> &&v)
{
    assert(!v.empty());
    std::sort(v.begin(), v.end());
    int64_t r = v[v.size() / 2];
    return r;
}

uintmax_t median(const std::vector<int64_t> &v)
{
    assert(!v.empty());
    std::vector<int64_t> v_copy(v);
    std::sort(v_copy.begin(), v_copy.end());
    int64_t r = v_copy[v_copy.size() / 2];
    return r;
}

long double covariance(const std::vector<int64_t> a, const std::vector<int64_t> &b)
{
    assert(a.size() == b.size());
    long double ma = mean(a);
    long double r = 0;
    long double mb = mean(b);
    for (size_t i = 0; i < a.size(); ++i)
        r += (a[i] - ma) * (b[i] - mb);
    return r / a.size();
}

long double standard_deviation(const std::vector<int64_t> &a)
{
    assert(a.size() > 0);
    long double ma = mean(a);
    long double r = 0;
    for(auto i : a) {
        auto diff = i - ma;
        r += diff * diff;
    }
    return std::sqrt(r / a.size());
}

long double standard_deviation(const std::vector<int64_t> &a, const std::vector<int64_t> &b)
{
    assert(a.size() > 0);
    assert(a.size() == b.size());
    long double r = 0;
    for(size_t i = 0; i < a.size(); ++i) {
        auto diff = a[i] - b[i];
        r += diff * diff;
    }
    return std::sqrt(r / a.size());
}

long double corrcoef(const std::vector<int64_t> &a, const std::vector<int64_t> &b)
{
    return covariance(a,b) / (standard_deviation(a) * standard_deviation(b));
}

bucket_distribution::bucket_distribution(int64_t min, int64_t max, size_t bucket_count, const std::vector<int64_t> &values)
    : _min(min), _max(max), _bucket_step((max - min) / bucket_count)
{
    this->_buckets.resize(bucket_count);

    for (auto v : values) {
        ++this->_buckets[this->bucket_index(v)];
    }
}

size_t bucket_distribution::bucket_index(int64_t v) const
{
    size_t raw_index = (v - this->_min) / this->_bucket_step;
    return std::clamp(raw_index, (size_t)0, this->_buckets.size() - 1);
}

long double bucket_distribution::corrcoef(bucket_distribution& d) {
    assert(d._min == this->_min);
    assert(d._max == this->_max);
    assert(d._bucket_step == this->_bucket_step);
    assert(d._buckets.size() == this->_buckets.size());
    return porc::stats::corrcoef(this->_buckets, d._buckets);
}

}
