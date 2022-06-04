#!/bin/bash
docker run --privileged --network=host --rm  -v "/etc/timezone:/etc/timezone:ro" -v"/etc/localtime:/etc/localtime:ro" -v /home/ubuntu/super/state/plugins/pfw:/state/plugins/pfw -v /home/ubuntu/super/configs/plugins/pfw/:/configs/plugins/pfw -v /home/ubuntu/super//configs/base:/configs/base/ --name superpfw pfw
