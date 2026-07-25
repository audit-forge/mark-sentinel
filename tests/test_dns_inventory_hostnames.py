"""Hostname attribution for DNS inventory source activity."""

from admin.dns_connector import connect


def test_nextdns_device_name_is_returned_alongside_local_ip():
    result = connect(
        log_content=(
            "timestamp,domain,query_type,client_ip,device_name,device_local_ip\n"
            "2026-07-23T12:00:00Z,api.openai.com,A,203.0.113.10,alice-laptop,192.168.1.20\n"
        )
    )

    assert result["by_source"]["192.168.1.20"] == ["api.openai.com"]
    assert result["source_hostnames"]["192.168.1.20"] == ["alice-laptop"]


def test_formats_without_hostname_leave_hostname_map_empty():
    result = connect(
        log_content=(
            "Jun 15 10:23:45 dnsmasq[1234]: query[A] api.openai.com from 192.168.1.5\n"
        )
    )

    assert result["by_source"]["192.168.1.5"] == ["api.openai.com"]
    assert result["source_hostnames"] == {}


def test_nextdns_hostname_only_source_is_retained():
    result = connect(
        log_content=(
            "timestamp,domain,query_type,client_ip,device_name,device_local_ip\n"
            "2026-07-23T12:00:00Z,claude.ai,A,,build-runner,\n"
        )
    )

    assert result["by_source"]["build-runner"] == ["claude.ai"]
    assert result["source_hostnames"]["build-runner"] == ["build-runner"]
