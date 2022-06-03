#!/bin/bash
docker run --privileged --network=host --rm -v /home/ubuntu/super/state/plugins/pfw:/state/plugins/pfw -v /home/ubuntu/super/configs/plugins/pfw/:/configs/plugins/pfw -v /home/ubuntu/super//configs/base:/configs/base/ --name superpfw pfw
