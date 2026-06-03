# Abschluss_2026_PLA-2_bursil_network_surveillance

## Projektidee

Überwachung von Netzwerkverkehr mit ML-Algorithmen. Die Algorithmen sollen C2 Verhalten erkennen können. C2 steht für Command and Control, damit können Angreifer Persistent auf ihren Opfergeräten bleiben und Befehle an diese schicken. C2 wird auch im Zusammenhang mit DDoS Attacken genutzt, um mit C2-Server viele Opfer-Geräte zu orchestrieren.
Die Umsetzung werde ich mit Python machen, da ich mich mit Python gut auskenne und Python auch guten ML Support hat. Mit Python lässt sich der Netzwerkverkehr auch gut aufzeichnen.

## Lernmöglichkeiten

- Vertieftes Wissen um C2 Architektur und Verhalten von solchen Strukturen
- Vertieftes Wissen um spezifische ML-Algorithmen
- ML mit Python kennenlernen
- Verschiedene Arten des Netzwerkmonitorings kennenlernen
## Milestones

1. Informationensammlung
Sammlung von Informationen über:
- Botnet Architektur
- Bereits vorhandene Tools für C2 Detection
- Vorteile/Nachteile von verschiedenen ML Algorithmen zb Isolation Forest oder MLP
- Welche Netzwerkdaten wichtig oder unwichtig für mein Projekt sind
- Ob Realtime Überwachung möglich/sinnvoll ist

2.  Prototyp erstellen
Prototyp erstellen der folgende Funktionen beinhalten soll:
- Nutzung eines ausgewählten Algorithmus
- Daten aus einer PCAP Datei auslesen
- Daten verarbeiten, Features extrahieren
- Mithilfe des Algorithmus erfolgreich C2 Verhalten erkennen
- C2 Verhalten simulieren mit Scripts

3. C2 Framework erkennen
Ein verbesserter Prototyp erstellen:
- Probleme und Engpässe beim alten Prototyp erkennen
- Lösungen für die gefundenen Probleme erarbeiten und implementieren
- Der Prototyp sollte ein echtes C2 Framework erkennen können

Optional:

Real-Time Detection implementieren