"""Crawl seeding tests (pure, network-free)."""

from hydra.attack import CrawlSeeder, param_signature


def test_dedup_by_param_signature():
    urls = ["https://x/search?q=1", "https://x/search?q=2",      # same signature → 1
            "https://x/item?id=1", "https://x/item?id=9",        # same signature → 1
            "https://x/static.js"]                                # no params → dropped (params_only)
    seeds = CrawlSeeder().seeds(urls)
    assert len(seeds) == 2
    sigs = {param_signature(u) for u in seeds}
    assert len(sigs) == 2


def test_params_only_can_be_disabled():
    urls = ["https://x/a", "https://x/b?q=1"]
    assert len(CrawlSeeder().seeds(urls, params_only=False)) == 2
    assert len(CrawlSeeder().seeds(urls, params_only=True)) == 1


def test_in_scope_host_filter():
    urls = ["https://app.acme.com/s?q=1", "https://evil.com/s?q=1"]
    seeds = CrawlSeeder().seeds(urls, in_scope_hosts=["acme.com"])
    assert seeds == ["https://app.acme.com/s?q=1"]


def test_max_seeds_cap():
    urls = [f"https://x/p{i}?a=1" for i in range(50)]
    assert len(CrawlSeeder().seeds(urls, max_seeds=10)) == 10


def test_param_signature_ignores_values_and_order():
    assert param_signature("https://x/p?a=1&b=2") == param_signature("https://x/p?b=9&a=8")
