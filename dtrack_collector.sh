#!/usr/bin/env bash

# Scans the images of running containers with Syft and uploads CycloneDX SBOMs
# to Dependency-Track. Configuration is persisted beside this script so cron
# jobs continue to work after a reboot.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"
CONFIG_FILE="${DTRACK_CONFIG_FILE:-$SCRIPT_DIR/dtrack_collector.env}"
LOG_FILE="${DTRACK_LOG_FILE:-$SCRIPT_DIR/dtrack_collector-scan.log}"
LOCK_FILE="${DTRACK_LOCK_FILE:-/tmp/dtrack_collector-docker-sbom.lock}"
CRON_MARKER="# dtrack_collector-docker-sbom"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:latest}"

log() {
	printf '%s %s\n' "$(date -Is)" "$*"
}

fail() {
	log "ERROR: $*" >&2
	exit 1
}

load_config() {
	if [[ -f "$CONFIG_FILE" ]]; then
		set -a
		# shellcheck disable=SC1090
		source "$CONFIG_FILE"
		set +a
	elif [[ -n "${DTRACK_API_URL:-}" && -n "${DTRACK_API_KEY:-}" ]]; then
		umask 077
		{
			printf 'DTRACK_API_URL=%q\n' "$DTRACK_API_URL"
			printf 'DTRACK_API_KEY=%q\n' "$DTRACK_API_KEY"
		} >"$CONFIG_FILE"
		chmod 600 "$CONFIG_FILE"
		log "Persisted Dependency-Track configuration in $CONFIG_FILE"
	fi

	[[ -n "${DTRACK_API_URL:-}" ]] || fail "DTRACK_API_URL is not set. Copy dtrack_collector.env.example to $CONFIG_FILE and set it."
	[[ -n "${DTRACK_API_KEY:-}" ]] || fail "DTRACK_API_KEY is not set. Copy dtrack_collector.env.example to $CONFIG_FILE and set it."

	DTRACK_CHECK_IMAGE_LATEST="${DTRACK_CHECK_IMAGE_LATEST:-false}"
	DTRACK_IMAGES="${DTRACK_IMAGES:-}"
	DTRACK_LATEST_CACHE_FILE="${DTRACK_LATEST_CACHE_FILE:-$SCRIPT_DIR/dtrack_collector-latest.cache}"
	DTRACK_LATEST_CACHE_TTL="${DTRACK_LATEST_CACHE_TTL:-86400}"

	case "$DTRACK_CHECK_IMAGE_LATEST" in
		true|false) ;;
		*) fail "DTRACK_CHECK_IMAGE_LATEST must be true or false" ;;
	esac

	[[ "$DTRACK_LATEST_CACHE_TTL" =~ ^[0-9]+$ ]] ||
		fail "DTRACK_LATEST_CACHE_TTL must be a non-negative number of seconds"
}

check_dependencies() {
	command -v docker >/dev/null || fail "docker is required"
	command -v curl >/dev/null || fail "curl is required"
	command -v flock >/dev/null || fail "flock is required"
}

check_docker_daemon() {
	docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"
}

install_cron() {
	command -v crontab >/dev/null || fail "crontab is required to install the schedule"

	local cron_line="0 4 * * * \"$SCRIPT_PATH\" --run >> \"$LOG_FILE\" 2>&1 $CRON_MARKER"
	local current_crontab
	current_crontab="$(crontab -l 2>/dev/null || true)"

	if grep -Fq -- "$CRON_MARKER" <<<"$current_crontab"; then
		log "Cron job is already installed"
		return
	fi

	printf '%s\n%s\n' "$current_crontab" "$cron_line" | crontab -
	log "Installed cron job: daily at 04:00"
}

cached_digest() {
	local reference="$1"
	local now
	local timestamp
	local cached_reference
	local digest

	[[ "$DTRACK_LATEST_CACHE_TTL" != "0" && -f "$DTRACK_LATEST_CACHE_FILE" ]] || return 1
	now="$(date +%s)"

	while IFS=$'\t' read -r timestamp cached_reference digest; do
		if [[ "$cached_reference" == "$reference" &&
			"$timestamp" =~ ^[0-9]+$ &&
			$((now - timestamp)) -le DTRACK_LATEST_CACHE_TTL ]]; then
			printf '%s\n' "$digest"
			return 0
		fi
	done <"$DTRACK_LATEST_CACHE_FILE"

	return 1
}

cache_digest() {
	local reference="$1"
	local digest="$2"
	local cache_directory
	local temp_file
	local timestamp
	local cached_reference
	local cached_digest

	[[ "$DTRACK_LATEST_CACHE_TTL" != "0" ]] || return
	cache_directory="$(dirname -- "$DTRACK_LATEST_CACHE_FILE")"
	if [[ ! -d "$cache_directory" ]]; then
		log "WARNING: cannot cache image digest; directory does not exist: $cache_directory"
		return
	fi

	temp_file="$(mktemp "$cache_directory/.dtrack_collector-latest.XXXXXX")" ||
		{ log "WARNING: cannot create image digest cache"; return; }
	if ! chmod 600 "$temp_file"; then
		log "WARNING: cannot secure image digest cache"
		rm -f -- "$temp_file"
		return
	fi

	if [[ -f "$DTRACK_LATEST_CACHE_FILE" ]]; then
		while IFS=$'\t' read -r timestamp cached_reference cached_digest; do
			if [[ "$cached_reference" != "$reference" ]] &&
				! printf '%s\t%s\t%s\n' "$timestamp" "$cached_reference" "$cached_digest" >>"$temp_file"; then
				log "WARNING: cannot update image digest cache"
				rm -f -- "$temp_file"
				return
			fi
		done <"$DTRACK_LATEST_CACHE_FILE"
	fi

	if ! printf '%s\t%s\t%s\n' "$(date +%s)" "$reference" "$digest" >>"$temp_file" ||
		! mv -- "$temp_file" "$DTRACK_LATEST_CACHE_FILE"; then
		log "WARNING: cannot update image digest cache"
		rm -f -- "$temp_file"
	fi
}

resolve_digest() {
	local reference="$1"
	local digest

	if digest="$(cached_digest "$reference")"; then
		printf '%s\n' "$digest"
		return
	fi

	if ! digest="$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$reference" 2>&1)"; then
		log "WARNING: could not resolve image digest for $reference: $digest" >&2
		return 1
	fi

	if [[ ! "$digest" =~ ^sha256:[[:xdigit:]]{64}$ ]]; then
		log "WARNING: registry returned an invalid image digest for $reference: $digest" >&2
		return 1
	fi

	cache_digest "$reference" "$digest"
	printf '%s\n' "$digest"
}

local_image_digests() {
	local image="$1"
	local repository="$2"
	local repo_digest
	local repo_name
	local found=false

	while IFS= read -r repo_digest; do
		[[ -n "$repo_digest" ]] || continue
		repo_name="${repo_digest%@*}"
		if [[ "$repo_name" == "$repository" ||
			"$repo_name" == "docker.io/$repository" ||
			"$repo_name" == "docker.io/library/$repository" ]]; then
			printf '%s\n' "${repo_digest##*@}"
			found=true
		fi
	done < <(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" 2>/dev/null)

	[[ "$found" == "true" ]]
}

check_image_latest() {
	local image="$1"
	local repository="$2"
	local version="$3"
	local local_digests
	local image_digest
	local latest_digest
	local tag_local_match=false
	local latest_local_match=false
	local is_latest=false

	PROJECT_IS_LATEST=""
	if [[ "$DTRACK_CHECK_IMAGE_LATEST" != "true" ]]; then
		log "Latest check disabled for $image (set DTRACK_CHECK_IMAGE_LATEST=true to enable)"
		return 0
	fi
	if [[ "$image" == *@* ]]; then
		log "Skipping latest check for $image; image is pinned by digest"
		return 0
	fi

	local_digests="$(local_image_digests "$image" "$repository")" || {
		log "Skipping latest check for $image; local image has no matching registry digests"
		return 0
	}

	if ! image_digest="$(resolve_digest "$repository:$version")"; then
		log "Latest check unavailable for $image; could not resolve $repository:$version"
		return 0
	fi
	if ! latest_digest="$(resolve_digest "$repository:latest")"; then
		log "Latest check unavailable for $image; could not resolve $repository:latest"
		return 0
	fi
	if grep -Fqx -- "$image_digest" <<<"$local_digests"; then
		tag_local_match=true
	fi
	if grep -Fqx -- "$latest_digest" <<<"$local_digests"; then
		latest_local_match=true
	fi
	if [[ "$tag_local_match" == "true" && "$latest_local_match" == "true" ]]; then
		is_latest=true
	fi
	PROJECT_IS_LATEST="$is_latest"

	log "Latest check: image=$image local_digests=$(tr '\n' ',' <<<"$local_digests") tag_digest=$image_digest tag_local_match=$tag_local_match latest_digest=$latest_digest latest_local_match=$latest_local_match is_latest=$is_latest"
}

project_details() {
	local image="$1"
	local repository="$image"
	local version="latest"
	local server_name

	if [[ "$image" == *@* ]]; then
		repository="${image%@*}"
		version="${image#*@}"
	elif [[ "${image##*/}" == *:* ]]; then
		repository="${image%:*}"
		version="${image##*:}"
	fi

	server_name="$(hostname -f 2>/dev/null || hostname)"
	PROJECT_NAME="$server_name/$repository"
	PROJECT_VERSION="$version"
	check_image_latest "$image" "$repository" "$version" || true
}

upload_bom() {
	local image="$1"
	local bom_file
	local response
	local project_uuid
	local project_uuid_pattern='"projectUuid"[[:space:]]*:[[:space:]]*"([^"]+)"'
	local -a project_latest_form=()

	project_details "$image"
	if [[ -n "$PROJECT_IS_LATEST" ]]; then
		project_latest_form=(--form "isLatest=$PROJECT_IS_LATEST")
	fi
	bom_file="$(mktemp)"
	trap 'rm -f -- "$bom_file"' RETURN

	log "Scanning $image"
	if ! docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		"$SYFT_IMAGE" "$image" -o cyclonedx-json >"$bom_file"; then
		log "ERROR: Failed to create an SBOM for $image"
		rm -f -- "$bom_file"
		trap - RETURN
		return 1
	fi

	if ! response="$(curl --fail-with-body --silent --show-error \
		--request POST "${DTRACK_API_URL%/}/api/v1/bom" \
		--header "X-Api-Key: $DTRACK_API_KEY" \
		--form "projectName=$PROJECT_NAME" \
		--form "projectVersion=$PROJECT_VERSION" \
		--form 'autoCreate=true' \
		"${project_latest_form[@]}" \
		--form "bom=@$bom_file;type=application/vnd.cyclonedx+json")"; then
		log "ERROR: Failed to upload the SBOM for $image${response:+: $response}"
		rm -f -- "$bom_file"
		trap - RETURN
		return 1
	fi

	log "Uploaded SBOM for $image (${response:-accepted})"
	if [[ -n "$PROJECT_IS_LATEST" ]]; then
		if [[ "$response" =~ $project_uuid_pattern ]]; then
			project_uuid="${BASH_REMATCH[1]}"
			if ! response="$(curl --fail-with-body --silent --show-error \
				--request PATCH "${DTRACK_API_URL%/}/api/v1/project/$project_uuid" \
				--header "X-Api-Key: $DTRACK_API_KEY" \
				--header 'Content-Type: application/json' \
				--data "{\"isLatest\":$PROJECT_IS_LATEST}")"; then
				log "WARNING: uploaded SBOM for $image but could not set project latest=$PROJECT_IS_LATEST${response:+: $response}" >&2
			else
				log "Set Dependency-Track project $project_uuid latest=$PROJECT_IS_LATEST"
			fi
		else
			log "WARNING: uploaded SBOM for $image but response did not contain a project UUID; project latest status was not updated" >&2
		fi
	fi
	rm -f -- "$bom_file"
	trap - RETURN
}

run_scan() {
	local image
	local failed=0
	local succeeded=0
	local -a images

	if [[ -n "$DTRACK_IMAGES" ]]; then
		read -r -a images <<<"$DTRACK_IMAGES"
		log "Scanning configured images: ${images[*]}"
	else
		mapfile -t images < <(docker ps --format '{{.Image}}' | sort -u)
	fi
	if ((${#images[@]} == 0)); then
		log "No images configured or running Docker containers found"
		return
	fi

	for image in "${images[@]}"; do
		if upload_bom "$image"; then
			((succeeded += 1))
		else
			((failed += 1))
		fi
	done

	log "Scan complete: $succeeded uploaded, $failed failed"
	((failed == 0))
}

main() {
	local mode="${1:---install-and-run}"

	case "$mode" in
		--help|-h)
			cat <<EOF
Usage: ./${SCRIPT_PATH##*/} [--install|--run]

Without arguments, stores exported DTRACK_API_URL and DTRACK_API_KEY in
dtrack_collector.env (when needed), installs the daily 04:00 cron schedule, and
runs a scan immediately. Cron reads dtrack_collector.env after every reboot.
EOF
			return
			;;
	esac

	load_config
	check_dependencies

	case "$mode" in
		--install)
			install_cron
			;;
		--run)
			check_docker_daemon
			exec 9>"$LOCK_FILE"
			flock -n 9 || { log "A scan is already running; skipping"; exit 0; }
			run_scan
			;;
		--install-and-run)
			install_cron
			check_docker_daemon
			exec 9>"$LOCK_FILE"
			flock -n 9 || { log "A scan is already running; skipping"; exit 0; }
			run_scan
			;;
		*)
			fail "unknown option: $mode"
			;;
	esac
}

main "$@"
