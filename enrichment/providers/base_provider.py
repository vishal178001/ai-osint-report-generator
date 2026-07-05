from abc import ABC, abstractmethod


class ThreatIntelligenceProvider(ABC):
    """
    Base interface for external threat-intelligence providers.
    """

    @abstractmethod
    def is_configured(self):
        """
        Return True when the provider has the required configuration.
        """
        pass

    @abstractmethod
    def check_ip(self, ip_address):
        """
        Check the reputation of an IP address.

        Implementations should return a dictionary and handle provider
        failures gracefully.
        """
        pass
