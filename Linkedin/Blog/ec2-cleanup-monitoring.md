# EC2 Cleanup & Monitoring

**Monitor • Review • Clean • Log**

## The Problem

An EC2 server was running low on disk space. I needed to clean it up without deleting important files or affecting running applications.

## How I Debugged It

Before cleaning, I checked:

- CPU and memory
- Disk usage
- EBS volumes
- Large files
- Running processes

## The Solution

I created a Python-based **EC2 Cleanup & Monitoring script** with:

- **Auto Mode** — runs predefined cleanup tasks
- **Interactive Mode** — reviews actions before cleanup
- **JSON Logging** — records what was cleaned

## My Approach

**Check → Review → Approve → Clean → Log**

This keeps the cleanup process safe and makes it easy to see what happened.

## What I Learned

EC2 cleanup should not be just **delete and move on**.

**Check first, clean safely, and keep a record.**

**Have you faced an EC2 disk-space issue? How did you handle it?**

---

**Blog:** https://vishnusai.hashnode.dev/ec2-cleanup-monitoring-monitor-review-clean-log  
**GitHub:** https://github.com/ksaivishnusaikvs/DevOps-Engineering/tree/main/Linkedin/Post

#AWS #EC2 #DevOps #CloudComputing #Linux #SRE
