# sock-drawer

Keeps things in boxes. A small URL archiver with frozen manifests, checked bundles, and resumable release checkpoints.

Run **Sweep** with a manifest release tag and its SHA256. Source downloads use anonymous HTTPS; release writes use the repository's own token. No installation or artifact storage is needed.

**Mill** runs a sealed offline toolbox on completed archives. Its key is a repository secret; toolbox files, results and diagnostics stay sealed in releases. It uses up to four CPU processes per job and resumes checked outputs. The full queue stays disabled until its small pilot has been independently checked.
