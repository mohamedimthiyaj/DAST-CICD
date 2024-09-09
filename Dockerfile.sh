# Dockerfile
FROM burpsuite-activated

# Ensure entrypoint is set correctly
ENTRYPOINT ["/root/app/entrypoint.sh"]