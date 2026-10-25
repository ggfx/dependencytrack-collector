 # Dependency-Track Collector

Collect software bills of materials (SBOMs) for running Docker containers and send them to [Dependency-Track](https://dependencytrack.org/) automatically.

The collector uses [Syft](https://github.com/anchore/syft) to create CycloneDX SBOMs, then uploads them to Dependency-Track. Each image is tracked as a project named after the host and image repository, with the image tag or digest as its version.

## Why use it?

Once the SBOMs are in Dependency-Track, you can:

- see the open-source components inside running containers;
- monitor known vulnerabilities and policy violations;
- identify affected projects when a component vulnerability is disclosed; and
- keep an inventory of what is actually deployed, rather than only what is built.

## Prerequisites

Before using the collector, deploy Dependency-Track somewhere that the Docker host can reach, for example on another server or using the [Dependency-Track Docker image](https://docs.dependencytrack.org/getting-started/deploy-docker/). Create an API key in that running Dependency-Track instance with permission `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO` and `BOM_UPLOAD`. To enable latest-project updates, the key also needs `PORTFOLIO_MANAGEMENT_UPDATE`.

## Quick start

Clone this repository to the Linux host running your containers. In addition to Docker, that host needs `curl`, `flock`, and `crontab`.

```bash
git clone https://github.com/ggfx/dependencytrack-collector.git
cd dependencytrack-collector

cp dtrack_collector.env.example dtrack_collector.env
chmod 600 dtrack_collector.env
${EDITOR:-vi} dtrack_collector.env
```

Set these values in `dtrack_collector.env`:

```dotenv
DTRACK_API_URL=https://dependency-track.example.com
DTRACK_API_KEY=your-api-key
```

Then start the collector:

```bash
./dtrack_collector.sh
```

Running the script without arguments performs an immediate scan and installs a daily cron job at 04:00. The script discovers the unique images used by running containers, scans them, and creates Dependency-Track projects automatically when needed.

### Scan selected images

To scan only specified images, set `DTRACK_IMAGES` to a whitespace-separated list in `dtrack_collector.env`. These images do not need to have running containers:

```dotenv
DTRACK_IMAGES="nginx:1.27 ghcr.io/example/service:v1.2.3"
```

When `DTRACK_IMAGES` is unset or empty, the collector retains its default behavior of scanning images used by running containers.

## Commands

```bash
./dtrack_collector.sh --run      # Scan now
./dtrack_collector.sh --install  # Install the daily schedule only
./dtrack_collector.sh --help
```

The installed cron job writes logs to `dtrack_collector-scan.log` beside the script; direct runs print to the terminal. The collector uses a lock file so overlapping scans are skipped.

## Optional latest-image checks

Set `DTRACK_CHECK_IMAGE_LATEST=true` to synchronize each checked project's latest status. Any tag (`latest`, a version, `stable`, etc.) is marked latest only when a local registry digest matches both that tag and the remote `:latest` tag; otherwise it is marked not latest. Images pinned by digest or without a registry digest, such as locally built images, are skipped without changing their project status. This option requires Docker Buildx (`docker buildx imagetools`) and an API key with `PORTFOLIO_MANAGEMENT_UPDATE`, because existing projects must be updated through the Project API. Registry lookups are cached for 24 hours by default; the cache location and lifetime can be changed in `dtrack_collector.env`.

## Security notes

Keep `dtrack_collector.env` readable only by the account that runs the collector. The scan needs access to the Docker daemon and mounts `/var/run/docker.sock` into the temporary Syft container, so run it only on a trusted host. Use a narrowly scoped Dependency-Track API key and protect the generated log file if image names are sensitive.
