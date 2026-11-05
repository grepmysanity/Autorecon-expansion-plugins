from sysreptor.plugins import PluginConfig


class AutoReconImportPluginConfig(PluginConfig):
    """
    Drag-and-drop import of AutoRecon results (the "sysreptor-overview" report: _sysreptor.json /
    _sysreptor_overview.json) and raw Nmap XML into a project: an additive notes tree, one target
    finding per IP (Service Enumeration; new findings get the design's template prompts), the Methodologies
    fields and an Appendix "Tools and Custom Scripts" citation. Never overwrites text you wrote.
    Community-compatible local plugin (2026-11-05); parsing happens in your browser.
    """

    plugin_id = 'f8b9a10b-5407-45ca-a5fa-b889532a2655'
