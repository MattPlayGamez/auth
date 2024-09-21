module.exports = {
    transform: {
      "^.+\\.js$": "babel-jest",  // Use babel-jest to transform JS files
    },
    transformIgnorePatterns: [
      "node_modules/(?!(nanoid)/)",  // Include specific modules for transformation
    ],
  };
  