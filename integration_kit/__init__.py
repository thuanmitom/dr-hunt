"""OutSight HuntCompiler Integration Kit (Phase I).

Documentation plus a reference consumer that runs on the integrator's side: it pulls (or receives) signed Hunting
Packs, re-validates them, substitutes placeholders, runs the hunts on Wazuh, Elastic or Splunk, and posts the 1-bit
feedback. It is example code: it never ships in the HuntCompiler image and never imports ``app``.
"""
