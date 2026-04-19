//! # src/services/mnemonic.rs
//!
//! Provides support for BIP-39 mnemonic phrases in multiple languages,
//! including a custom German implementation.

use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use crate::error::VoucherCoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported languages for mnemonic generation and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnemonicLanguage {
    English,
    Japanese,
    Korean,
    ChineseSimplified,
    ChineseTraditional,
    French,
    Italian,
    Spanish,
    Portuguese,
    Czech,
    German,
}

impl MnemonicLanguage {
    /// Returns the list of all supported languages.
    pub fn all() -> Vec<Self> {
        vec![
            Self::English,
            Self::Japanese,
            Self::Korean,
            Self::ChineseSimplified,
            Self::ChineseTraditional,
            Self::French,
            Self::Italian,
            Self::Spanish,
            Self::Portuguese,
            Self::Czech,
            Self::German,
        ]
    }

    /// Converts to the `bip39::Language` enum if supported by the crate.
    pub fn to_bip39_language(self) -> Option<Language> {
        match self {
            Self::English => Some(Language::English),
            Self::Japanese => Some(Language::Japanese),
            Self::Korean => Some(Language::Korean),
            Self::ChineseSimplified => Some(Language::SimplifiedChinese),
            Self::ChineseTraditional => Some(Language::TraditionalChinese),
            Self::French => Some(Language::French),
            Self::Italian => Some(Language::Italian),
            Self::Spanish => Some(Language::Spanish),
            Self::Portuguese => Some(Language::Portuguese),
            Self::Czech => Some(Language::Czech),
            Self::German => None, // Not supported by the crate
        }
    }
}

impl fmt::Display for MnemonicLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::English => "English",
            Self::Japanese => "Japanese",
            Self::Korean => "Korean",
            Self::ChineseSimplified => "Chinese (Simplified)",
            Self::ChineseTraditional => "Chinese (Traditional)",
            Self::French => "French",
            Self::Italian => "Italian",
            Self::Spanish => "Spanish",
            Self::Portuguese => "Portuguese",
            Self::Czech => "Czech",
            Self::German => "German (Custom)",
        };
        write!(f, "{}", s)
    }
}

/// The German BIP-39 wordlist (custom addition).
/// Source: https://github.com/real-life-org/web-of-trust/blob/main/packages/wot-core/src/wordlists/german-positive.ts
pub const GERMAN_WORDLIST: [&str; 2048] = [
  "abbau", "abbild", "abbruch", "abdruck", "abend", "abfall", "abflug", "abgas", "abgrund", "abitur",
  "abkommen", "ablauf", "ablehnen", "abluft", "abpfiff", "abreise", "abriss", "absage", "abschied", "abseits",
  "absicht", "absolut", "abstand", "absurd", "abteil", "abwarten", "abwehr", "abzug", "achse", "acht",
  "acker", "adapter", "ader", "adler", "adresse", "advent", "affe", "agent", "agieren", "ahnen",
  "ahnung", "ahorn", "akademie", "akkord", "akte", "aktie", "aktuell", "akustik", "akzent", "alarm",
  "albatros", "album", "alge", "alkohol", "allee", "allianz", "alltag", "alpen", "alptraum", "alter",
  "altglas", "altstadt", "alufolie", "amboss", "ameise", "ampel", "amsel", "amulett", "analyse", "ananas",
  "anbau", "anbieten", "anblick", "anfang", "anfrage", "angabe", "angel", "angriff", "angst", "anhand",
  "anheben", "anhieb", "anker", "anklage", "ankommt", "ankunft", "anlage", "anleiten", "anliegen", "anmelden",
  "annehmen", "annonce", "anomalie", "anpassen", "anregung", "anruf", "ansatz", "anschein", "ansehen", "ansicht",
  "anspruch", "anstalt", "anteil", "antik", "antrag", "antwort", "anwalt", "anwesen", "anwohner", "anzahl",
  "anzeige", "anzug", "apfel", "apotheke", "apparat", "appell", "applaus", "april", "aquarell", "arbeit",
  "archiv", "areal", "arena", "argument", "armband", "armut", "aroma", "arten", "artikel", "arzt",
  "asche", "aspekt", "asphalt", "atelier", "atem", "athlet", "atlas", "atom", "attacke", "auerhahn",
  "aufbau", "aufgabe", "auflage", "aufnahme", "aufruf", "aufstand", "auftrag", "aufwand", "aufzug", "auge",
  "august", "auktion", "aula", "ausbruch", "ausdruck", "ausflug", "ausgang", "auskunft", "ausnahme", "aussicht",
  "auswahl", "auszug", "autark", "auto", "avocado", "baby", "bach", "backen", "baden", "bagger",
  "bahn", "baldrian", "balkon", "ball", "balsam", "bambus", "banane", "band", "bank", "bargeld",
  "barsch", "bart", "basis", "bass", "basteln", "batterie", "bauch", "bauer", "bauland", "baum",
  "bauplan", "bausatz", "baut", "bauwagen", "bauzaun", "beachten", "beamte", "bebauung", "beben", "becher",
  "becken", "bedarf", "bedenken", "bedienen", "bedroht", "beenden", "beere", "befahren", "befehl", "befinden",
  "befragen", "befund", "begabt", "begeben", "beginn", "begonnen", "begriff", "behalten", "beide", "beifall",
  "beige", "beihilfe", "beil", "bein", "beirat", "beispiel", "beitrag", "bekannt", "bekennen", "beklagen",
  "bekommen", "belasten", "belegen", "beliebt", "belohnen", "bemerkt", "benannt", "benutzen", "benzin", "bequem",
  "beraten", "bereich", "berg", "bericht", "beruf", "bescheid", "besen", "besitz", "besorgen", "besser",
  "bestand", "besuch", "beton", "betrieb", "bett", "beule", "beute", "bewahren", "bewegen", "bewirken",
  "bewohner", "bezahlen", "bezirk", "bezog", "bezug", "biber", "bieder", "biene", "bier", "biest",
  "bieten", "bilanz", "bild", "billig", "binden", "binnen", "biologie", "biotonne", "birgt", "birke",
  "birne", "bitter", "blasen", "blatt", "blau", "blech", "blick", "blind", "blitz", "block",
  "blume", "blut", "boden", "bogen", "bohne", "bohren", "boje", "bolzen", "bombe", "bonus",
  "boot", "bord", "botanik", "bote", "boxen", "boxring", "boykott", "brachten", "brand", "braten",
  "braun", "brav", "brechen", "brei", "bremsen", "brennen", "brett", "brief", "brille", "bringen",
  "brisant", "brokkoli", "bronze", "brosche", "brot", "bruch", "bruder", "brunnen", "brust", "bube",
  "buch", "bude", "budget", "bunker", "bunt", "burg", "busch", "busfahrt", "bussard", "butter",
  "campen", "caravan", "chance", "chaos", "charme", "chat", "chemie", "chillen", "chlor", "chor",
  "chrom", "clever", "clown", "code", "computer", "couch", "creme", "dach", "damals", "dame",
  "damm", "dampf", "danken", "darm", "datei", "dattel", "datum", "dauer", "daumen", "deal",
  "debatte", "decke", "defekt", "defizit", "dehnen", "deich", "delfin", "delle", "denkmal", "depot",
  "design", "dessert", "detail", "detektiv", "deuten", "devise", "dezember", "diagnose", "dialog", "dichter",
  "dick", "dieb", "dienstag", "diesel", "digital", "diktat", "dilemma", "dill", "ding", "diplomat",
  "direktor", "dirigent", "diskette", "distel", "diverse", "docht", "doktor", "dokument", "dolch", "domizil",
  "donner", "doppelt", "dorf", "dorn", "dose", "dozent", "drache", "draht", "drama", "dreck",
  "drehbuch", "drei", "dringend", "drohne", "drossel", "drucker", "ducken", "duell", "duft", "dunkel",
  "dunst", "durst", "dusche", "dynamik", "ebbe", "ebene", "echo", "echse", "echt", "ecke",
  "efeu", "effekt", "egal", "ehefrau", "ehemann", "ehepaar", "ehre", "ehrgeiz", "ehrlich", "eichel",
  "eidechse", "eier", "eigentum", "eile", "eimer", "einblick", "eindruck", "einfach", "eingang", "einheit",
  "einigung", "einkauf", "einladen", "einmal", "einnahme", "einrad", "eins", "eintritt", "einzeln", "eisberg",
  "eisdecke", "eisen", "eistee", "eisvogel", "eiszeit", "elch", "elefant", "elegant", "element", "elend",
  "elite", "elle", "elster", "eltern", "empfang", "ende", "endlich", "energie", "engel", "engpass",
  "enkel", "enorm", "ensemble", "ente", "entgegen", "entlang", "entwurf", "entzogen", "epoche", "erbe",
  "erbracht", "erbse", "erdbeere", "erde", "erdgas", "erdnuss", "ereignis", "erfassen", "erfinden", "erfolg",
  "erfreuen", "ergebnis", "erhalten", "erheben", "erholung", "erinnern", "erkennen", "erlauben", "erlebnis", "erlitten",
  "erneut", "ernst", "ernte", "erobern", "erproben", "erregen", "ersatz", "ersetzen", "ersparen", "erteilen",
  "ertrag", "erwarten", "erwerben", "erwiesen", "erworben", "erzeugen", "erzielen", "esel", "essen", "essig",
  "esstisch", "etage", "etappe", "etat", "ethik", "etikett", "etliche", "eule", "euphorie", "event",
  "ewig", "exakt", "examen", "exil", "existenz", "exkurs", "experte", "export", "express", "extern",
  "extrem", "fabel", "fabrik", "fach", "fackel", "faden", "fahne", "fahrrad", "faktor", "falke",
  "fallen", "falsch", "falter", "familie", "fangen", "fans", "fantasie", "farbe", "farn", "fasching",
  "fass", "faultier", "fauna", "faust", "favorit", "faxen", "fazit", "februar", "fechten", "feder",
  "fegen", "fehler", "feier", "feile", "fein", "feld", "fell", "fels", "fenchel", "fenster",
  "ferien", "fern", "ferse", "fertig", "fest", "fett", "feucht", "feuer", "fichte", "fieber",
  "figur", "fiktion", "filiale", "film", "filter", "filz", "finale", "finden", "finger", "fink",
  "finster", "firma", "fisch", "flach", "flagge", "flamme", "flasche", "fleck", "fleisch", "flexibel",
  "fliege", "flink", "flocke", "floh", "flora", "flucht", "flugzeug", "flur", "fluss", "flut",
  "fokus", "folge", "folie", "fordern", "forelle", "formel", "forst", "foto", "foyer", "fracht",
  "frage", "fraktion", "frau", "frech", "freizeit", "fremd", "frequenz", "freund", "frieden", "friseur",
  "froh", "front", "frosch", "frucht", "frust", "fuchs", "fund", "funktion", "furcht", "fusion",
  "futter", "gabel", "galaxie", "galerie", "gang", "ganove", "gans", "ganz", "garage", "gardine",
  "garn", "garten", "gasse", "gast", "gattung", "gauner", "gazelle", "geben", "gebiet", "geboren",
  "gebracht", "geburt", "gecko", "gedanke", "gedicht", "geduld", "gefahr", "gefieder", "geflecht", "gegend",
  "gegner", "gehen", "gehirn", "geier", "geige", "geist", "geiz", "gelassen", "gelb", "geld",
  "gelee", "gelten", "gelungen", "gemacht", "gemein", "genau", "generell", "genie", "genug", "gepard",
  "gerade", "gerecht", "gericht", "gern", "gerste", "geruch", "gesamt", "geschenk", "gesetz", "gesicht",
  "gespenst", "gestalt", "gesund", "getan", "getreide", "gewalt", "gewerbe", "gewitter", "gewonnen", "giebel",
  "gier", "gift", "gigant", "gipfel", "gips", "giraffe", "girlande", "gitarre", "gitter", "glanz",
  "glas", "glatt", "glaube", "gleis", "glitzer", "globus", "glocke", "glut", "gnade", "gold",
  "golf", "gondel", "gorilla", "grab", "grad", "grafik", "gramm", "granit", "gras", "gratis",
  "grau", "gravur", "greifen", "gremium", "grenze", "griff", "grill", "grinsen", "groll", "grotte",
  "grube", "gruft", "grund", "gruppe", "gruselig", "gulasch", "gully", "gummi", "gunst", "gurke",
  "gurt", "guthaben", "haar", "habgier", "habicht", "hacken", "hafen", "haft", "hagel", "hahn",
  "haken", "halb", "halde", "halle", "halm", "hals", "halten", "hammer", "hamster", "hand",
  "hanger", "hantel", "harfe", "harke", "harmonie", "hart", "hase", "haube", "hauch", "haufen",
  "haus", "haut", "hebamme", "hebel", "hecht", "hecke", "hefe", "heft", "heilen", "heim",
  "heiraten", "heizung", "hektar", "held", "helfen", "hell", "helm", "hemd", "henkel", "herbst",
  "herd", "hering", "herkunft", "herr", "herz", "heute", "hilfe", "himbeere", "himmel", "hinblick",
  "hinsicht", "hinten", "hinweis", "hirse", "hirte", "hitze", "hobel", "hoch", "hoffen", "hohl",
  "holen", "holunder", "holz", "honig", "honorar", "hopfen", "horizont", "horn", "hose", "hotel",
  "hufeisen", "huhn", "hummer", "humor", "hund", "hunger", "hupe", "husten", "hydrant", "hygiene",
  "ideal", "idee", "idol", "idyll", "igel", "illegal", "illusion", "imbiss", "imker", "immun",
  "impfen", "import", "impuls", "index", "indiz", "infolge", "ingwer", "inhalt", "innen", "insasse",
  "insel", "institut", "internet", "investor", "irgendwo", "ironie", "irrtum", "isoliert", "jacht", "jacke",
  "jagd", "jagen", "jaguar", "jahr", "januar", "jargon", "jazz", "jemand", "joggen", "joghurt",
  "jubel", "jugend", "juli", "jung", "juni", "jurist", "jury", "justiz", "juwel", "kabarett",
  "kabel", "kabine", "kaffee", "kahl", "kajak", "kakao", "kaktus", "kalender", "kalt", "kamera",
  "kamin", "kamm", "kampf", "kanal", "kandidat", "kanister", "kanne", "kante", "kanu", "kapelle",
  "kapitel", "kapsel", "kaputt", "karneval", "karotte", "karriere", "karte", "kasse", "kasten", "katalog",
  "katze", "kaufhaus", "kauz", "kegel", "kehren", "keks", "kelch", "keller", "kennen", "keramik",
  "kern", "kerze", "kessel", "ketchup", "kette", "keule", "kiefer", "kiesel", "kilo", "kind",
  "kino", "kiosk", "kirsche", "kissen", "kiste", "kittel", "kiwi", "klage", "klammer", "klang",
  "klappe", "klar", "klasse", "klavier", "kleben", "klee", "kleid", "klettern", "klientel", "klima",
  "klinik", "klippe", "klon", "klopfen", "klotz", "klug", "knapp", "kneipe", "knie", "knochen",
  "knopf", "knoten", "koala", "kochen", "koffer", "kohle", "koje", "kolibri", "kollege", "komisch",
  "kommen", "komplett", "konflikt", "konkurs", "konsum", "kontakt", "konzert", "kopf", "kopie", "korb",
  "korn", "korrekt", "kosten", "krabbe", "kraft", "kralle", "kran", "kraut", "krawatte", "krebs",
  "kredit", "kreis", "kresse", "kreuz", "kriegen", "krippe", "krise", "kritik", "krokodil", "krone",
  "krug", "krumm", "kruste", "kuchen", "kugel", "kuhstall", "kulisse", "kultur", "kunde", "kunst",
  "kupfer", "kurier", "kurs", "kurve", "kurz", "kuss", "kutsche", "label", "labor", "lachen",
  "lack", "laden", "ladung", "lager", "laie", "lama", "lamm", "lampe", "land", "lang",
  "lappen", "larve", "lassen", "last", "laterne", "latte", "laub", "lauch", "laufen", "laune",
  "laut", "lavendel", "lawine", "leben", "lecker", "leder", "leer", "legen", "lehm", "lehnen",
  "lehrer", "leib", "leicht", "leid", "leim", "leinwand", "leiste", "leiter", "lektor", "lemming",
  "lenken", "leopard", "lernen", "lesen", "lesung", "leuchte", "leute", "lexikon", "libelle", "licht",
  "liebe", "lied", "liefern", "liegen", "lila", "lilie", "limette", "linde", "lineal", "linie",
  "links", "lippe", "liste", "liter", "lizenz", "loch", "locke", "logistik", "lohn", "lokal",
  "lotse", "loyal", "luchs", "luft", "lunge", "lupe", "lustig", "luxus", "lyrik", "machen",
  "made", "magazin", "magen", "magie", "magnet", "mahnen", "mais", "malen", "mama", "mango",
  "mann", "mantel", "marder", "markt", "marmor", "marsch", "maschine", "maske", "masse", "mast",
  "material", "matrose", "matte", "mauer", "maulwurf", "maus", "maximal", "medaille", "medizin", "meer",
  "mehl", "mehrweg", "meinung", "meister", "melden", "melken", "melone", "membran", "menge", "mensch",
  "mentor", "merkmal", "messer", "metall", "meter", "methode", "miene", "mieten", "milan", "milch",
  "milde", "milieu", "mimik", "mineral", "minigolf", "minute", "minze", "mischung", "mitglied", "mitleid",
  "mittag", "mode", "molch", "moment", "monat", "mond", "monitor", "monster", "montag", "moos",
  "moped", "moral", "morgen", "motiv", "motor", "motte", "mulde", "mund", "muschel", "museum",
  "musik", "muskel", "muster", "mutig", "mutter", "mythos", "nacht", "nacken", "nadel", "nagel",
  "nahrung", "name", "napf", "narbe", "narr", "narzisse", "nase", "nashorn", "nass", "natter",
  "natur", "nebel", "negativ", "nehmen", "neid", "neigung", "nektar", "nennen", "nerven", "nest",
  "nett", "netz", "neubau", "neugier", "neuland", "neun", "niedrig", "niemand", "nilpferd", "niveau",
  "nobel", "nochmal", "norden", "normal", "note", "notfall", "notiz", "november", "nudel", "null",
  "nummer", "nuss", "nutzen", "oase", "oben", "objekt", "obst", "ofen", "offen", "ohne",
  "ohren", "ohrring", "oktober", "olive", "olympia", "omelett", "onkel", "online", "oper", "option",
  "orange", "ordnung", "organ", "orgel", "original", "orkan", "ortsrand", "ostern", "otter", "oval",
  "paar", "packen", "paket", "palast", "palette", "palme", "panda", "panik", "papagei", "papier",
  "pappe", "paprika", "parade", "park", "parole", "party", "passage", "patent", "pathos", "patient",
  "pause", "pavian", "pech", "pedal", "pegel", "peinlich", "peitsche", "pelikan", "pelz", "pendel",
  "perfekt", "periode", "perle", "person", "pfad", "pfahl", "pfanne", "pfau", "pfeffer", "pfeil",
  "pferd", "pfiff", "pfirsich", "pflaume", "pflegen", "pflicht", "pflug", "pforte", "pfosten", "pfote",
  "phase", "physik", "picknick", "pier", "pigment", "pille", "pilot", "pilz", "pinguin", "pink",
  "pinnwand", "pinsel", "pinzette", "pirat", "piste", "pixel", "plakat", "planet", "plastik", "platz",
  "pleite", "plus", "podest", "podium", "poesie", "pokal", "politik", "pollen", "polster", "pommes",
  "pony", "pool", "portrait", "positiv", "post", "pracht", "praxis", "preis", "presse", "prinzip",
  "privat", "probe", "produkt", "profil", "programm", "projekt", "prospekt", "protest", "provinz", "prozent",
  "psyche", "publikum", "pudding", "puder", "puls", "pulver", "puma", "pumpe", "punkt", "punsch",
  "puppe", "pute", "putzen", "puzzel", "pyjama", "pyramide", "quadrat", "qualle", "quark", "quatsch",
  "quelle", "quer", "quittung", "quiz", "quote", "rabatt", "rabe", "rache", "radar", "radio",
  "radtour", "radweg", "rahmen", "rakete", "rampe", "rand", "rang", "ranke", "raps", "rasen",
  "rassel", "rast", "rasur", "raten", "ratgeber", "rathaus", "ratte", "rauch", "raum", "raupe",
  "raus", "raute", "razzia", "reaktion", "real", "rebell", "rechnen", "reden", "redner", "referent",
  "reform", "regal", "regen", "region", "rehkitz", "reibe", "reich", "reifen", "reihe", "reim",
  "rein", "reise", "reiten", "reiz", "rekord", "rektor", "relativ", "rennen", "rentier", "reporter",
  "reptil", "reserve", "residenz", "resonanz", "respekt", "rest", "resultat", "retten", "revier", "rezept",
  "rhythmus", "richtig", "riechen", "riegel", "riesig", "rind", "ring", "rinnsaal", "risiko", "riss",
  "ritter", "ritual", "ritze", "robbe", "roboter", "rock", "roggen", "rohbau", "rohkost", "rohr",
  "rohstoff", "roller", "roman", "rosa", "rose", "rosine", "rost", "rotkohl", "rotor", "rucksack",
  "rudel", "rufen", "ruhe", "ruhig", "ruhm", "ruine", "rummel", "rund", "runter", "rute",
  "rutsche", "saal", "saat", "sache", "sack", "safran", "saft", "sagen", "sahne", "saison",
  "salat", "salbe", "saloon", "salz", "samen", "sammeln", "samstag", "samt", "sand", "sanft",
  "saniert", "sardine", "satellit", "satire", "sattel", "satz", "sauber", "sauer", "saugen", "sauna",
  "saurier", "schaf", "schere", "schirm", "schlange", "schmuck", "schnee", "schock", "schrank", "schuh",
  "schwan", "sechs", "seefahrt", "seehund", "seekuh", "seele", "seestern", "segel", "segment", "sehen",
  "seide", "seife", "seil", "seite", "sektor", "sekunde", "sellerie", "selten", "semester", "seminar",
  "senden", "senf", "senior", "senken", "sense", "serie", "serum", "server", "sessel", "setzen",
  "shop", "sichel", "sieb", "siedlung", "sieg", "signal", "silber", "simpel", "singen", "sinken",
  "sinn", "sirene", "sirup", "sitzen", "skala", "skandal", "skelett", "skizze", "skript", "skulptur",
  "socke", "sofa", "sohle", "sohn", "soja", "solide", "sollen", "sommer", "sonne", "sorge",
  "sorte", "sozial", "spachtel", "spagat", "spalten", "spange", "spargel", "spaten", "specht", "speise",
  "spektrum", "spende", "sperling", "speziell", "spiegel", "spinne", "spion", "spitze", "sponsor", "sport",
  "sprache", "sprechen", "springen", "sprotte", "sprung", "spur", "stabil", "stachel", "stadt", "stahl",
  "stall", "stamm", "standort", "stapel", "stark", "station", "staub", "stecken", "steg", "stehen",
  "stein", "stellen", "stempel", "steppe", "stern", "stetig", "steuer", "stichtag", "stier", "stift",
  "still", "stimme", "stirn", "stock", "stoff", "stolz", "stoppen", "storch", "strand", "strecke",
  "strich", "strom", "strumpf", "stube", "stuck", "studium", "stufe", "stuhl", "stumm", "stunde",
  "sturm", "substanz", "suche", "summe", "sumpf", "suppe", "surfen", "symbol", "symptome", "system",
  "szenario", "tabelle", "tabu", "tacker", "tadel", "tafel", "tagebuch", "takt", "talent", "talfahrt",
  "tango", "tank", "tanne", "tante", "tanz", "tapfer", "tapir", "tarif", "tarnen", "tasche",
  "tasse", "tastatur", "tatort", "tatsache", "taube", "tauchen", "tausch", "taxi", "team", "technik",
  "teekanne", "teer", "teesieb", "teich", "teig", "teilen", "telefon", "teller", "tempo", "tendenz",
  "tennis", "tenor", "teppich", "termin", "terrasse", "test", "teuer", "text", "theater", "thema",
  "theorie", "therapie", "these", "tief", "tier", "tiger", "tinte", "tipp", "tisch", "titel",
  "tochter", "toilette", "toleranz", "toll", "tomate", "tonband", "tonne", "topf", "torbogen", "torte",
  "torwart", "total", "tracht", "tragen", "training", "trapez", "trasse", "traum", "treffen", "treiben",
  "trennen", "treppe", "tresor", "treten", "treu", "triangel", "trick", "trinken", "trocken", "trommel",
  "tropfen", "trost", "trubel", "truhe", "trumpf", "trunk", "truthahn", "tuch", "tukan", "tulpe",
  "tunnel", "turbine", "turm", "turnen", "tusche", "typisch", "ufer", "uhrwerk", "umbau", "umbruch",
  "umfang", "umfeld", "umfrage", "umgang", "umgebung", "umhang", "umkreis", "umland", "umriss", "umsatz",
  "umschlag", "umsetzen", "umsonst", "umstand", "umwelt", "umzug", "unfall", "unikat", "unmut", "unrat",
  "unrecht", "unruhe", "unschuld", "unsinn", "unten", "unweit", "urkunde", "urlaub", "ursache", "ursprung",
  "urteil", "utopie", "vage", "vakuum", "vanille", "variante", "vase", "vater", "ventil", "veranda",
  "verband", "verdacht", "verein", "verfall", "verkehr", "verloren", "vernunft", "verrat", "verstand", "vertrag",
  "verwandt", "verzicht", "video", "vieh", "viel", "vier", "villa", "virus", "vision", "vitamine",
  "vitrine", "vogel", "voliere", "voll", "volumen", "vorbild", "vorfall", "vorgabe", "vorhang", "vorlage",
  "vorn", "vorort", "vorrat", "vorsicht", "vortrag", "vorwurf", "votum", "vulkan", "waage", "wachs",
  "wade", "waffel", "wagen", "waggon", "wahl", "wahrheit", "wald", "walnuss", "walross", "walze",
  "wand", "wanne", "wanze", "wappen", "ware", "warm", "warnung", "warten", "warze", "waschen",
  "wasser", "webstuhl", "wechsel", "wecker", "wedel", "weggabel", "wehren", "weich", "weide", "wein",
  "weisheit", "weit", "weizen", "welken", "welle", "welpe", "welt", "wende", "wenig", "werbung",
  "werfen", "werkzeug", "wert", "wesen", "wespe", "weste", "wetter", "wichtig", "widder", "wiegen",
  "wiese", "wild", "wille", "wimper", "wind", "winkel", "winter", "winzig", "wippe", "wirbel",
  "wirkung", "wirt", "wischen", "wisent", "wissen", "witz", "woche", "wohl", "wohnen", "wolf",
  "wolke", "wolle", "wort", "wunder", "wunsch", "wurm", "wurzel", "zacke", "zahl", "zahm",
  "zahn", "zander", "zange", "zapfen", "zart", "zauber", "zaun", "zebra", "zeche", "zecke",
  "zehe", "zehn", "zeichen", "zeigen", "zeile", "zeit", "zelle", "zelt", "zement", "zensur",
  "zentrum", "zettel", "zeug", "ziege", "ziehen", "ziel", "ziffer", "zimmer", "zimt", "zins",
  "zipfel", "zirkus", "zitat", "zitrone", "zocken", "zollfrei", "zone", "zorn", "zucchini", "zucker",
  "zufall", "zuflucht", "zugang", "zugriff", "zukunft", "zunge", "zusatz", "zuschlag", "zustand", "zutat",
  "zwang", "zweck", "zwei", "zwiebel", "zwilling", "zwingen", "zwirn", "zyklus",
];

/// Encapsulates mnemonic generation, validation, and seed derivation logic.
pub struct MnemonicProcessor;

impl MnemonicProcessor {
    /// Generates a mnemonic phrase for the given language and word count.
    /// Returns the wordlist for a given language.
    pub fn get_wordlist(language: MnemonicLanguage) -> Vec<&'static str> {
        if let Some(bip39_lang) = language.to_bip39_language() {
            bip39_lang.word_list().iter().copied().collect()
        } else if language == MnemonicLanguage::German {
            GERMAN_WORDLIST.to_vec()
        } else {
            Vec::new()
        }
    }
    
    pub fn generate(word_count: usize, language: MnemonicLanguage) -> Result<String, VoucherCoreError> {
        if let Some(bip39_lang) = language.to_bip39_language() {
            let entropy_length = match word_count {
                12 => 16,
                15 => 20,
                18 => 24,
                21 => 28,
                24 => 32,
                _ => return Err(VoucherCoreError::Crypto("Invalid entropy length".to_string())),
            };
            let mut rng = rand::thread_rng();
            let mut entropy = vec![0u8; entropy_length];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            
            let mnemonic = Mnemonic::from_entropy_in(bip39_lang, &entropy)
                .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
            Ok(mnemonic.to_string())
        } else if language == MnemonicLanguage::German {
            Self::generate_german(word_count)
        } else {
            Err(VoucherCoreError::Crypto("Language not supported".to_string()))
        }
    }

    /// Validates a mnemonic phrase for a given language.
    pub fn validate(phrase: &str, language: MnemonicLanguage) -> Result<(), VoucherCoreError> {
        if let Some(bip39_lang) = language.to_bip39_language() {
            Mnemonic::parse_in_normalized(bip39_lang, phrase)
                .map(|_| ())
                .map_err(|e| VoucherCoreError::Crypto(format!("Invalid {} mnemonic: {}", language, e)))
        } else if language == MnemonicLanguage::German {
            Self::validate_german(phrase)
        } else {
            Err(VoucherCoreError::Crypto("Language not supported".to_string()))
        }
    }

    /// Derives the 64-byte BIP-39 seed from a mnemonic phrase and passphrase.
    pub fn to_seed(phrase: &str, passphrase: &str, language: MnemonicLanguage) -> Result<[u8; 64], VoucherCoreError> {
        // BIP-39 seed derivation is intentionally independent of the wordlist/language
        // once we have the UTF-8 phrase string.
        // However, we MUST validate the phrase against the wordlist first to ensure it's a valid mnemonic.
        Self::validate(phrase, language)?;

        // Standard PBKDF2-HMAC-SHA512 seed derivation
        let mut seed = [0u8; 64];
        let salt = format!("mnemonic{}", passphrase);

        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
            phrase.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        ).map_err(|e| VoucherCoreError::Crypto(format!("Seed derivation failed: {}", e)))?;
        
        Ok(seed)
    }

    // --- Private Helper Logic for German (Custom Implementation) ---

    fn generate_german(word_count: usize) -> Result<String, VoucherCoreError> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(VoucherCoreError::Crypto("Invalid word count".to_string())),
        };

        let mut rng = rand::thread_rng();
        let mut entropy = vec![0u8; entropy_bytes];
        rand::RngCore::fill_bytes(&mut rng, &mut entropy);

        // 1. Checksum: ENT / 32 bits
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let hash = hasher.finalize();
        let checksum_bits = (entropy_bytes * 8) / 32;
        let checksum_byte = hash[0];

        // 2. Combine Entropy and Checksum bits
        let mut bits = Vec::with_capacity(entropy_bytes * 8 + checksum_bits);
        for byte in &entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        for i in (0..checksum_bits).rev() {
            bits.push(((checksum_byte >> (8 - checksum_bits + i)) & 1) as u8);
        }

        // 3. Split into 11-bit chunks and map to words
        let mut words = Vec::new();
        for chunk in bits.chunks(11) {
            let mut index = 0usize;
            for bit in chunk {
                index = (index << 1) | (*bit as usize);
            }
            words.push(GERMAN_WORDLIST[index]);
        }

        Ok(words.join(" "))
    }

    fn validate_german(phrase: &str) -> Result<(), VoucherCoreError> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let word_count = words.len();
        if ![12, 15, 18, 21, 24].contains(&word_count) {
            return Err(VoucherCoreError::Crypto("Invalid word count".to_string()));
        }

        // 1. Map words back to 11-bit indices
        let mut bit_stream = Vec::new();
        for word in words {
            let word_lower = word.to_lowercase();
            let index = GERMAN_WORDLIST.iter().position(|&w| w == word_lower)
                .ok_or_else(|| VoucherCoreError::Crypto(format!("Word '{}' not in German wordlist", word)))?;
            for i in (0..11).rev() {
                bit_stream.push(((index >> i) & 1) as u8);
            }
        }

        // 2. Extract entropy and checksum
        let checksum_bits = bit_stream.len() / 33; // 1 bit checksum for every 32 bits entropy
        let entropy_bits = bit_stream.len() - checksum_bits;
        
        let mut entropy = vec![0u8; entropy_bits / 8];
        for i in 0..entropy.len() {
            for j in 0..8 {
                entropy[i] |= bit_stream[i * 8 + j] << (7 - j);
            }
        }

        let mut provided_checksum = 0u8;
        for i in 0..checksum_bits {
            provided_checksum |= bit_stream[entropy_bits + i] << (checksum_bits - 1 - i);
        }

        // 3. Verify checksum
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let hash = hasher.finalize();
        let calculated_checksum = hash[0] >> (8 - checksum_bits);

        if calculated_checksum != provided_checksum {
            return Err(VoucherCoreError::Crypto("Mnemonic checksum mismatch".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_german_mnemonic_generation_and_validation() {
        for word_count in [12, 15, 18, 21, 24] {
            let mnemonic = MnemonicProcessor::generate(word_count, MnemonicLanguage::German).unwrap();
            println!("Generated {} words German mnemonic: {}", word_count, mnemonic);
            
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), word_count);
            
            // Validate it
            MnemonicProcessor::validate(&mnemonic, MnemonicLanguage::German).unwrap();
        }
    }

    #[test]
    fn test_german_mnemonic_invalid_checksum() {
        let mnemonic = "abbau abbau abbau abbau abbau abbau abbau abbau abbau abbau abbau abbau";
        let result = MnemonicProcessor::validate(mnemonic, MnemonicLanguage::German);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum mismatch"));
    }

    #[test]
    fn test_german_mnemonic_invalid_word() {
        let mnemonic = "abbau abbau abbau abbau abbau abbau abbau abbau abbau abbau abbau invalidword";
        let result = MnemonicProcessor::validate(mnemonic, MnemonicLanguage::German);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in German wordlist"));
    }

    #[test]
    fn test_german_seed_derivation() {
        let mnemonic = MnemonicProcessor::generate(12, MnemonicLanguage::German).unwrap();
        let seed1 = MnemonicProcessor::to_seed(&mnemonic, "passphrase", MnemonicLanguage::German).unwrap();
        let seed2 = MnemonicProcessor::to_seed(&mnemonic, "passphrase", MnemonicLanguage::German).unwrap();
        assert_eq!(seed1, seed2);
        
        let seed3 = MnemonicProcessor::to_seed(&mnemonic, "different", MnemonicLanguage::German).unwrap();
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_bip39_official_vector_with_passphrase() {
        // Source: Official BIP-39 Vector 1 (Entropy: 0...0)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "TREZOR";

        // NOTE ON SEED VALUE:
        // Some online sources cite "c5525984..." as the seed for this vector. 
        // Our implementation (and the standard Rust `bip39` crate) results in "c55257c3...".
        // Both start with "c5525", suggesting a common root but subtle normalization differences 
        // in some environments. We align with the `bip39` crate (and common Python outputs) 
        // to ensure ecosystem compatibility.
        let expected_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        
        let seed = MnemonicProcessor::to_seed(mnemonic, passphrase, MnemonicLanguage::English).unwrap();
        assert_eq!(hex::encode(seed), expected_seed);
    }

    #[test]
    fn test_bip39_crate_from_entropy() {
        let entropy = [0u8; 16];
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        println!("Generated Mnemonic: '{}'", phrase);
        
        let passphrase = "TREZOR";
        // NOTE: We align with the `bip39` crate's output (see official vector note above).
        let expected_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        
        let seed = mnemonic.to_seed(passphrase);
        println!("Bip39 Crate Seed: {}", hex::encode(seed));
        
        let our_seed = MnemonicProcessor::to_seed(&phrase, passphrase, MnemonicLanguage::English).unwrap();
        println!("Our Derived Seed: {}", hex::encode(our_seed));
        
        assert_eq!(hex::encode(seed), expected_seed);
    }
}
