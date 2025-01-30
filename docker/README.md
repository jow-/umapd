# Docker Testbed

This directory contains definitions for a basic docker-compose based testbed in
order to quickly build and test umapd in a virtual environment.

The testbed relies on the host kernels mac80211_hwsim to spawn virtual,
connected radio phys which can be managed by the OpenWrt rootfs based
docker container images.

## Setup

To build and run the container environment, execute the following commands
within the docker directory:

    $ sudo modprobe mac80211_hwsim
    $ COMPOSE_PROJECT_NAME=umap DOCKER_BUILDKIT=1 docker-compose up
