FROM node:22.16.0-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Expose the port
EXPOSE 3001

# Start the application
CMD ["npm", "run", "dev"]