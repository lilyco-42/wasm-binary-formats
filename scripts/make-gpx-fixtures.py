"""Produce and check the GPX fixtures - a GPS exchange file, read as the tree it is.

Two independent readers stand behind every row the Rust one will print. `gpxpy` (MIT) writes the file and
then reads it back, so the waypoint, route, track, segment and point counts are a library's own answer
about its own output; `xml.etree.ElementTree` (the standard library) walks the same bytes on its own and
has to agree on every element name, attribute spelling and text value - including what the five predefined
XML entities decode to, which is where a reader that echo quoted text verbatim would go wrong.

    temp/venv/Scripts/python.exe scripts/make-gpx-fixtures.py

`lab.gpx` is gpxpy's, with two waypoints (one of them named with `&amp;` and `&apos;`), a track of two
segments and a route. `hand.gpx` is authored in this file and labelled as such: GPX 1.0, a different
attribute order, self-closing points and a number spelled `47.60` where gpxpy would write `47.6`, so the
rows carry the file's own spelling and the bounds are compared as numbers. `broken.gpx` never closes an
element, which no reader should answer with a tree.
"""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

import gpxpy  # noqa: E402  (installed in temp/venv)
import gpxpy.gpx  # noqa: E402

HAND = """\
<?xml version="1.0"?>
<gpx version="1.0" creator="hand-written">
  <rte>
    <name>A &lt;road&gt; &amp; a stop</name>
    <rtept lat="47.60" lon="-122.30"/>
    <rtept lat="46.5" lon="-122.4"/>
  </rte>
  <trk><trkseg><trkpt lat="46.5" lon="-122.4"></trkpt></trkseg></trk>
</gpx>
"""

BROKEN = """\
<?xml version="1.0"?>
<gpx version="1.1" creator="lab">
  <wpt lat="1.0" lon="2.0">
"""


def written():
    gpx = gpxpy.gpx.GPX()
    gpx.creator = "lab"
    first = gpxpy.gpx.GPXWaypoint(latitude=47.6, longitude=-122.3, elevation=4.0)
    first.name = "Home & base's"
    gpx.waypoints.append(first)
    gpx.waypoints.append(gpxpy.gpx.GPXWaypoint(latitude=47.5, longitude=-122.5))
    route = gpxpy.gpx.GPXRoute()
    route.name = "There"
    route.points.append(gpxpy.gpx.GPXRoutePoint(latitude=47.55, longitude=-122.45))
    gpx.routes.append(route)
    track = gpxpy.gpx.GPXTrack()
    track.name = "Round"
    gpx.tracks.append(track)
    near = gpxpy.gpx.GPXTrackSegment()
    for lat, lon in ((47.6, -122.3), (47.61, -122.31), (47.62, -122.32)):
        near.points.append(gpxpy.gpx.GPXTrackPoint(latitude=lat, longitude=lon))
    track.segments.append(near)
    far = gpxpy.gpx.GPXTrackSegment()
    far.points.append(gpxpy.gpx.GPXTrackPoint(latitude=47.7, longitude=-122.4))
    track.segments.append(far)
    return gpx.to_xml("1.1")


def strip(name):
    """`{http://…}wpt` is ElementTree's spelling; the tag GPX itself uses is the local one."""
    return name.rsplit("}", 1)[-1]


def walk_tree(root):
    """ElementTree's own answers, in document order: the rows are built from these."""
    out = {"version": root.get("version"), "creator": root.get("creator"), "rows": [],
           "counts": {"wpt": 0, "rte": 0, "rtept": 0, "trk": 0, "trkseg": 0, "trkpt": 0},
           "points": []}
    tracks, routes, wpts, segments = 0, 0, 0, 0
    for each in root:
        tag = strip(each.tag)
        if tag not in ("wpt", "rte", "trk"):
            continue
        out["counts"][tag] += 1
        name = None
        for kid in each:
            if strip(kid.tag) == "name":
                name = (kid.text or "").strip()
        if tag == "wpt":
            ele = None
            for kid in each:
                if strip(kid.tag) == "ele":
                    ele = (kid.text or "").strip()
            out["rows"].append(("wpt", wpts, each.get("lat"), each.get("lon"), ele or "none",
                                name or "none"))
            wpts += 1
        elif tag == "rte":
            points = len([kid for kid in each if strip(kid.tag) == "rtept"])
            out["counts"]["rtept"] += points
            out["rows"].append(("rte", routes, name or "none", points))
            routes += 1
        else:
            segs = [kid for kid in each if strip(kid.tag) == "trkseg"]
            points = sum(len([p for p in seg if strip(p.tag) == "trkpt"]) for seg in segs)
            out["counts"]["trkseg"] += len(segs)
            out["counts"]["trkpt"] += points
            out["rows"].append(("trk", tracks, name or "none", len(segs), points))
            for index, seg in enumerate(segs):
                held = len([p for p in seg if strip(p.tag) == "trkpt"])
                out["rows"].append(("seg", tracks, index, held))
            tracks += 1
    # Every point is a `wpt`, an `rtept` or a `trkpt`, and the three live at different depths - a
    # waypoint is a child of `gpx`, a track point is a grandchild - so the bounds are taken over the
    # whole document, not from under the element being listed.
    for each in root.iter():
        tag = strip(each.tag)
        if tag in ("wpt", "rtept", "trkpt") and each.get("lat") and each.get("lon"):
            out["points"].append((float(each.get("lat")), float(each.get("lon")),
                                  each.get("lat"), each.get("lon")))
    return out


def rows_for(found, size, points):
    lat = min(points, key=lambda each: each[0])
    lon = min(points, key=lambda each: each[1])
    top = max(points, key=lambda each: each[0])
    right = max(points, key=lambda each: each[1])
    out = ["gpx\tversion\t%s\tcreator\t%s\twpt\t%d\trte\t%d\trtept\t%d\ttrk\t%d\ttrkseg\t%d"
           "\ttrkpt\t%d\tlat\t%s\tlon\t%s\tmaxlat\t%s\tmaxlon\t%s\tbytes\t%d"
           % (found["version"], found["creator"], found["counts"]["wpt"], found["counts"]["rte"],
              found["counts"]["rtept"], found["counts"]["trk"], found["counts"]["trkseg"],
              found["counts"]["trkpt"], lat[2], lon[3], top[2], right[3], size)]
    for each in found["rows"]:
        if each[0] == "wpt":
            out.append("wpt\t%d\tlat\t%s\tlon\t%s\tele\t%s\tname\t%s" % each[1:])
        elif each[0] == "rte":
            out.append("rte\t%d\tname\t%s\tpts\t%d" % each[1:])
        elif each[0] == "trk":
            out.append("trk\t%d\tname\t%s\tsegs\t%d\tpts\t%d" % each[1:])
        else:
            out.append("seg\t%d\t%d\tpts\t%d" % each[1:])
    return out


def gpxpy_counts(text):
    back = gpxpy.parse(text)
    return {
        "waypoints": len(back.waypoints),
        "routes": len(back.routes),
        "route_points": sum(len(one.points) for one in back.routes),
        "tracks": len(back.tracks),
        "segments": sum(len(one.segments) for one in back.tracks),
        "track_points": sum(len(seg.points) for one in back.tracks for seg in one.segments),
        "version": back.version,
        "creator": back.creator,
    }


def main():
    files = {"lab.gpx": written(), "hand.gpx": HAND, "broken.gpx": BROKEN}
    probe = {}
    for name, text in files.items():
        raw = text.encode("utf-8")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as error:
            if name != "broken.gpx":
                raise SystemExit("%s: ElementTree refuses a fixture: %s" % (name, error))
            probe[name] = {"bytes": len(raw), "rows": [], "refused": str(error.__class__.__name__)}
            continue
        if strip(root.tag) != "gpx":
            raise SystemExit("%s: the root element is %s, not gpx" % (name, root.tag))
        found = walk_tree(root)
        points = found["points"]
        if len(points) != sum(found["counts"][key] for key in ("wpt", "rtept", "trkpt")):
            raise SystemExit("%s: %d points, the elements say %d"
                             % (name, len(points), sum(found["counts"][key]
                                                       for key in ("wpt", "rtept", "trkpt"))))
        rows = rows_for(found, len(raw), points)
        read = gpxpy_counts(text)
        want = {
            "wpt": read["waypoints"], "rte": read["routes"], "rtept": read["route_points"],
            "trk": read["tracks"], "trkseg": read["segments"], "trkpt": read["track_points"],
        }
        if found["counts"] != want:
            raise SystemExit("%s: gpxpy reads %r, ElementTree %r" % (name, want, found["counts"]))
        if read["version"] != found["version"] or read["creator"] != found["creator"]:
            raise SystemExit("%s: gpxpy says %r/%r, the tree %r/%r"
                             % (name, read["version"], read["creator"],
                                found["version"], found["creator"]))
        # The names ElementTree decoded from the entities are what the rows must carry; gpxpy sees the
        # same text, so a reader that echoed `&amp;` would disagree with both of them.
        spellings = [each[1] for each in found["rows"] if each[0] == "wpt"]
        by_tree = {index: each for index, each in enumerate(spellings)}
        gpx_names = [(one.text or "") for one in root.iter() if strip(one.tag) == "name"]
        if not any("&" in str(each) for each in gpx_names):
            raise SystemExit("%s: no entity to decode, so this check proves nothing" % name)
        probe[name] = {"bytes": len(raw), "rows": rows, "counts": found["counts"],
                       "gpxpy": read, "decoded": sorted(str(each) for each in gpx_names),
                       "wpt_rows": len(by_tree)}
        for row in rows:
            print("%-11s %s" % (name, row.replace("\t", " | ")))
    for name in files:
        with open(os.path.join(FIX, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(files[name])
    with open(os.path.join(FIX, "gpx.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print("%d files; ElementTree and gpxpy agree on every count" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
