# BASELINE - intentionally insecure (exercise: see FIXES.md, V21-V27)

# [V21] Old, full-fat Debian image: compilers, git, curl, wget, python... all shipped to prod.
FROM node:22.2.0-bookworm

WORKDIR /app

# [V23] COPY . . drags in .env.production, id_deploy, .git and everything else.
COPY . .

# [V24] 'npm install' (not 'npm ci'): non-reproducible, and devDependencies end up in the image.
RUN npm install

# [V25] SSH port exposed on an app container.
EXPOSE 22 3000

# [V26] No USER instruction -> the app runs as root.   [V27] No HEALTHCHECK.
CMD ["npm", "start"]
