"""SOC engine: deterministic detection and correlation for Windows and Ubuntu logs.

Flow:  log files -> parsers -> events -> maintenance filter -> rules -> alerts -> correlation -> incidents
Nothing in this package changes any system: the output is a report for the operator.
"""
__version__ = "0.1.0"
