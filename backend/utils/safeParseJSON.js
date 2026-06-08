function safeParseJSON(raw) {
  try {
    let cleaned = raw.replace(/```json|```/gi, "").trim();

    const firstObj = cleaned.indexOf("{");
    const firstArr = cleaned.indexOf("[");

    let first;
    let last;

    if (firstArr !== -1 && (firstArr < firstObj || firstObj === -1)) {
      first = firstArr;
      last = cleaned.lastIndexOf("]");
    } else {
      first = firstObj;
      last = cleaned.lastIndexOf("}");
    }

    if (first === -1 || last === -1) {
      throw new Error("No valid JSON found");
    }

    cleaned = cleaned.slice(first, last + 1);

    const parsed = JSON.parse(cleaned);

    if (Array.isArray(parsed)) {
      return { items: parsed };
    }

    return parsed;
  } catch (e) {
    console.error("❌ JSON PARSE FAILED");
    console.error(raw);
    return { items: [] };
  }
}

module.exports = safeParseJSON;
