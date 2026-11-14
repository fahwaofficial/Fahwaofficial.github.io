{
  "name": "ifzi-mining-worker",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "deploy": "wrangler deploy",
    "dev": "wrangler dev",
    "check": "tsc --noEmit"
  },
  "dependencies": {
    "@ton/core": "^0.60.0",
    "@ton/ton": "^15.1.0",
    "@noble/curves": "^1.8.1"
  },
  "devDependencies": {
    "wrangler": "^4.0.0",
    "typescript": "^5.7.0"
  }
}
