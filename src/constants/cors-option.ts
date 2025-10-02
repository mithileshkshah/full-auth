export const CORS_OPTION = {
  origin: ["http://localhost:3000", "http://localhost:4200"], // allowed origins
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"], // allowed methods
  allowedHeaders: ["Content-Type", "Authorization"], // allowed headers
  credentials: true, // for cookies or authentication headers,
  optionsSuccessStatus: 200, // for older browsers
};
