# File: /etc/cron.d/production-disk-cleanup

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

############################################################
# Production Cleanup (Every 10 Days)
############################################################

############################
# Docker Cleanup
############################

# 02:00 AM - Remove stopped containers older than 10 days.
0 2 */10 * * docker container prune -f --filter "until=240h"

# 02:05 AM - Remove unused images older than 10 days.
5 2 */10 * * docker image prune -a -f --filter "until=240h"

# 02:10 AM - Remove unused Docker networks older than 10 days.
10 2 */10 * * docker network prune -f --filter "until=240h"

# 02:15 AM - Remove Docker build cache older than 10 days.
15 2 */10 * * docker builder prune -f --filter "until=240h"

# 02:20 AM - Remove all unused Docker volumes.
# Docker volume prune does not support time-based filtering.
20 2 */10 * * docker volume prune -f

############################
# Linux Cleanup
############################

# 03:00 AM - Remove unused Linux packages.
0 3 */10 * * apt autoremove -y

# 03:05 AM - Remove old APT package cache.
5 3 */10 * * apt autoclean -y

# 03:10 AM - Keep only the last 30 days of system logs.
10 3 */10 * * journalctl --vacuum-time=30d

# 03:15 AM - Delete temporary files older than 10 days.
15 3 */10 * * find /tmp -type f -mtime +10 -delete
