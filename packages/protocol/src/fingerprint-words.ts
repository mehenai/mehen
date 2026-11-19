// The word list and colour palette behind fingerprintWords (fingerprint.ts).
// Data, never code: the order is the encoding, so a word or colour may be
// replaced only by one at the same index, and never while a fingerprint
// derived from the list is still being compared somewhere.
//
// Words: exactly 256 (one per byte), common concrete nouns in British
// spelling, 4 to 6 lower-case letters, no two within one edit of each other,
// no homophones of another everyday word, no colour names (including
// materials and foods used as colours: gold, salmon, peach and the like, so
// a word never reads as a colour beside the dot), and nothing sad, rude or
// alarming. They are read aloud across a room and off a watch face, so they
// must also sound different from one another.

export const FINGERPRINT_WORDS: readonly string[] = [
  "acorn", "almond", "anchor", "apple", "apron", "atlas", "attic", "badger",
  "bagel", "bakery", "bamboo", "banana", "banjo", "banner", "barn", "barrel",
  "basil", "basket", "beaver", "beetle", "bench", "bike", "birch", "book",
  "bottle", "bowl", "branch", "brush", "bucket", "buckle", "bulb", "butter",
  "button", "cabin", "cactus", "camel", "camera", "canal", "candle", "canoe",
  "canvas", "canyon", "card", "carpet", "cashew", "castle", "cave", "cedar",
  "cello", "chair", "cheese", "chess", "clock", "cloud", "clover", "collar",
  "comb", "comet", "corgi", "cork", "couch", "crab", "cradle", "crane",
  "crayon", "curry", "daisy", "desert", "dish", "doll", "domino", "donkey",
  "door", "drawer", "dress", "drum", "eagle", "easel", "engine", "falcon",
  "farm", "fence", "fern", "ferret", "ferry", "field", "floor", "flute",
  "folder", "fridge", "frog", "fudge", "garden", "garlic", "gate", "globe",
  "goat", "goose", "grass", "guitar", "hammer", "harp", "hedge", "helmet",
  "hill", "hippo", "holly", "hound", "husky", "igloo", "iron", "island",
  "jacket", "jelly", "juice", "jungle", "kayak", "kettle", "kite", "kitten",
  "kiwi", "koala", "ladder", "lagoon", "lake", "lamp", "laptop", "leaf",
  "letter", "lily", "lizard", "llama", "lorry", "lotus", "maple", "marble",
  "market", "meadow", "meteor", "mirror", "moon", "moth", "mouse", "oasis",
  "onion", "otter", "oven", "page", "palace", "panda", "pantry", "papaya",
  "paper", "parcel", "parrot", "pasta", "path", "patio", "peanut", "pebble",
  "pencil", "pepper", "petal", "photo", "piano", "pigeon", "pillow", "pizza",
  "planet", "plate", "plug", "pony", "poodle", "potato", "puffin", "puppy",
  "purse", "puzzle", "quilt", "rabbit", "radio", "raisin", "reef", "rhino",
  "ribbon", "rice", "river", "robin", "robot", "rocket", "rope", "ruler",
  "saddle", "salad", "sandal", "scarf", "screw", "seal", "sheep", "shell",
  "shirt", "shovel", "sink", "sleeve", "snail", "sofa", "soup", "spade",
  "sponge", "spoon", "stamp", "star", "stone", "stool", "stream", "street",
  "sugar", "swan", "switch", "table", "tandem", "tank", "teapot", "teddy",
  "temple", "tent", "thread", "ticket", "tiger", "tile", "toast", "torch",
  "towel", "train", "tray", "tripod", "trophy", "trout", "truck", "tulip",
  "tunnel", "turtle", "tweed", "twig", "valley", "velvet", "vinyl", "violin",
  "waffle", "wagon", "wallet", "window", "wire", "yacht", "yogurt", "zebra",
]

// A colour shown as a dot beside a word. `light` is the hex to draw on a
// white or off-white surface, `dark` the hex to draw on a near-black one;
// each is readable against its own surface. The name is spoken, so the
// sixteen names are chosen to sound different from one another.
export type FingerprintColour = { name: string; light: string; dark: string }

export const FINGERPRINT_COLOURS: readonly FingerprintColour[] = [
  { name: "red", light: "#c62828", dark: "#ff6b6b" },
  { name: "coral", light: "#d9532b", dark: "#ff9b7a" },
  { name: "orange", light: "#d96c00", dark: "#ffa040" },
  { name: "amber", light: "#a87600", dark: "#ffc940" },
  { name: "olive", light: "#6b7a1f", dark: "#b5c441" },
  { name: "green", light: "#1c6e3d", dark: "#6fd391" },
  { name: "mint", light: "#1f8a6e", dark: "#7fe0c1" },
  { name: "teal", light: "#00758f", dark: "#4fd0e8" },
  { name: "sky", light: "#1a7fcf", dark: "#7fc4ff" },
  { name: "blue", light: "#2c56c9", dark: "#8fb0ff" },
  { name: "indigo", light: "#3f3fb5", dark: "#a3a3ff" },
  { name: "violet", light: "#6a3fb5", dark: "#c39bff" },
  { name: "magenta", light: "#b5179e", dark: "#ff7ae6" },
  { name: "pink", light: "#d6336c", dark: "#ff9bbf" },
  { name: "brown", light: "#7b4a1e", dark: "#d4a070" },
  { name: "grey", light: "#5f636b", dark: "#b8bcc4" },
]
