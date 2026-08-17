# Helm chart

Kubernetes deployment. Scheduled M6.

The worker needs a container runtime socket, which is root-equivalent on the
node — schedule it to a dedicated node pool, and prefer the rootless Podman
driver when it lands.
