# Papaya Network Protocol
Typescript

# Specifications
- **Base:** TCP
- **Port:** 947
- **Encryption:** TLS (Specifications later)
- **Headers:**
  - VER(sion)
  - CON(tent)
  - LEN(gth) (might not need it if the data format isn't binary)
  - to expand...
- **Data format:**
  - JSON (for now, later could use binary)
- **Error handling:**
  - Error codes could be the same as HTTP error codes because of common understanding