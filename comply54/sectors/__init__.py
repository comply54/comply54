from ._base import SectorCompliance
from .kenya_fintech import KenyaFintechCompliance
from .nigeria_fintech import NigeriaFintechCompliance
from .nigeria_health import NigeriaHealthcareCompliance
from .nigeria_insurance import NigeriaInsuranceCompliance
from .pan_african import PanAfricanFintechCompliance

__all__ = [
    "KenyaFintechCompliance",
    "NigeriaFintechCompliance",
    "NigeriaHealthcareCompliance",
    "NigeriaInsuranceCompliance",
    "PanAfricanFintechCompliance",
    "SectorCompliance",
]
