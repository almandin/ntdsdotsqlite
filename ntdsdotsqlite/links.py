from collections import defaultdict


def compute_links(ese_db):
    links = ese_db.table("link_table")
    relations = defaultdict(list)
    for link in links.records():
        flink = link.get("link_DNT")
        blink = link.get("backlink_DNT")
        # relations[flink].append(blink)
        relations[blink].append(flink)
    return relations
