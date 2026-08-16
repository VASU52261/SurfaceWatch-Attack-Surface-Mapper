"""
reports/
--------
Human-readable reporting layer for SurfaceWatch.

This package turns the technical output of the attack surface graph
(graph/builder.py) into language a non-technical business owner can act on.

Modules
    plain_english.py : converts graph analysis into plain English findings
    attack_story.py  : turns attack paths into readable narratives (Phase 2)
    pdf_generator.py : renders a professional PDF report (Phase 5)

Convenience re-exports are loaded lazily (PEP 562) so that running a
submodule directly — ``python -m reports.plain_english`` — does not import it
twice.
"""

__all__ = [
    "Finding",
    "Severity",
    "cvss_to_severity",
    "friendly_name",
    "generate_findings",
    "generate_report",
    "format_report_text",
]


def __getattr__(name: str):
    """Import the plain English helpers only when they are actually used."""
    if name in __all__:
        from reports import plain_english
        return getattr(plain_english, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
