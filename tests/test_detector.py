"""
Test suite for the network analyzer.
"""

import os
import pytest
from pathlib import Path
from network_analyzer.detector import NetworkLogAnomalyDetector
from network_analyzer.config import Config
from network_analyzer.utils.helpers import shannon_entropy, is_private_ip

@pytest.fixture
def test_pcap():
    """Fixture providing test PCAP file path."""
    return os.path.join('test_pcaps', '2019-02-07-cred-stealer-via-FTP-traffic.pcap')

@pytest.fixture
def config():
    """Fixture providing test configuration."""
    return Config()

@pytest.mark.asyncio
async def test_detector_initialization(test_pcap, config):
    """Test detector initialization."""
    detector = NetworkLogAnomalyDetector(test_pcap)
    assert detector.pcap_path == test_pcap
    assert detector.total_packets == 0

def test_shannon_entropy():
    """Test Shannon entropy calculation."""
    assert shannon_entropy('') == 0.0
    assert shannon_entropy('aaaa') == 0.0
    assert shannon_entropy('abcd') > 0.0

def test_is_private_ip():
    """Test private IP detection."""
    assert is_private_ip('192.168.1.1')
    assert is_private_ip('10.0.0.1')
    assert not is_private_ip('8.8.8.8')
    assert not is_private_ip('invalid_ip')
