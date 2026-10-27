"""Preserve original pages, text and whole-page vision evidence separately."""
import json
import re
import shutil
from pathlib import Path
from ..common import ICPError, append_jsonl, atomic_write, command, digest, file_hash, save_json


def text_reliable(text):
    visible = [c for c in text if not c.isspace()]
    return len(visible) >= 20 and sum(c.isprintable() and c != "\ufffd" for c in visible) / len(visible) > .97


def ocr_page(image, backend, config, destination):
    if backend == "tesseract":
        return command(["tesseract", str(image), "stdout", "-l", config.get("ocr_languages", "eng")], timeout=config.get("ocr_timeout_seconds", 180))
    if backend == "paddle":
        # In offline mode only an explicitly local pipeline configuration is accepted.
        pipeline_config = config.get("paddle_pipeline_config")
        if config.get("offline") and not pipeline_config:
            raise ICPError("Offline Paddle requires a local pipeline config with all model paths", "offline")
        try:
            from paddleocr import PPStructureV3
        except ImportError as exc:
            raise ICPError("Install the layout extra for PP-StructureV3", "dependency") from exc
        options = {"device": config.get("paddle_device", "cpu")}
        if pipeline_config:
            options["paddlex_config"] = pipeline_config
            if config.get("offline"):
                from ..common import load_mapping
                pipeline = load_mapping(Path(pipeline_config).read_text())
                rendered = json.dumps(pipeline)
                if "http://" in rendered or "https://" in rendered:
                    raise ICPError("Offline Paddle configuration contains remote resources", "offline")
                def local_models(node):
                    if isinstance(node, dict):
                        for key, value in node.items():
                            if key.endswith("_model_dir") and value:
                                model_path = Path(value)
                                if not model_path.is_absolute():
                                    model_path = Path(pipeline_config).parent / model_path
                                if not model_path.is_dir():
                                    raise ICPError("Offline Paddle model directory is missing: " + str(model_path), "offline")
                            local_models(value)
                    elif isinstance(node, list):
                        for value in node:
                            local_models(value)
                local_models(pipeline)
                for key in ("layout_detection_model_dir", "text_detection_model_dir", "text_recognition_model_dir"):
                    if key not in rendered:
                        raise ICPError("Offline Paddle config must pin local " + key, "offline")
        elif config.get("offline"):
            raise ICPError("Offline Paddle requires a local PP-StructureV3 paddlex_config", "offline")
        pipeline = PPStructureV3(**options)
        destination.mkdir(parents=True, exist_ok=True)
        outputs = list(pipeline.predict(input=str(image)))
        for result in outputs:
            result.save_to_markdown(save_path=str(destination))
            result.save_to_json(save_path=str(destination))
        texts = [item.markdown.get("markdown_texts", "") for item in outputs]
        if not texts or not any(texts):
            raise ICPError("Paddle produced no Markdown")
        return "\n".join(texts)
    raise ICPError("Unknown OCR backend: " + backend, "configuration")


def _semantic_boundaries(pages, config, model, document_id, root):
    maximum = config["document"]["max_context_chars"]
    budget = max(500, int(maximum * .45))
    blocks, current, chars = [], [], 0
    for page in pages:
        size = len(page["text"])
        if current and (chars + size > budget or len(current) >= config["document"]["secondary_split_pages"]):
            if not current[-1]["continues_to_next"]:
                blocks.append(current); current, chars = [], 0
            elif chars + size > maximum * .85:
                raise ICPError("A cross-page table exceeds semantic segmentation context; increase document.max_context_chars")
        if size > maximum * .55:
            raise ICPError("A page is too large for semantic segmentation; increase the configured model context")
        current.append(page); chars += size
    if current:
        blocks.append(current)
    starts = set()
    for block in blocks:
        first, last = block[0]["number"], block[-1]["number"]
        result = model.call("text", "segmentation", {"document_id": document_id,
            "page_range": {"start_page": first, "end_page": last},
            "pages": [{"page_number": p["number"], "text": p["text"]} for p in block]})
        boundaries = result.get("boundaries")
        if not isinstance(boundaries, list) or any(type(value) is not int for value in boundaries):
            raise ICPError("Semantic segmentation boundaries must be integer PDF page numbers", "model_format", True)
        if boundaries != sorted(set(boundaries)) or any(value <= first or value > last for value in boundaries):
            raise ICPError("Semantic segmentation returned unordered/out-of-range page boundaries", "model_format", True)
        for value in boundaries:
            page = pages[value - 1]
            if page["continues_from_previous"]:
                append_jsonl(root / "diagnostics.jsonl", {"stage": "segmentation", "document_id": document_id,
                             "page_number": value, "decision": "discarded boundary inside cross-page continuation"})
                continue
            starts.add(value)
    return sorted(starts)


def prepare_documents(config, root, model):
    try:
        import fitz
    except ImportError as exc:
        raise ICPError("Install the documents extra (PyMuPDF)", "dependency") from exc
    root = Path(root)
    docroot = root / "document"
    sources, segments, registry, full = {}, [], [], []
    if not config["specifications"]:
        raise ICPError("No specification PDFs configured", "configuration")
    for spec in config["specifications"]:
        original = Path(spec["path"])
        sha = file_hash(original)
        snapshot = root / "sources" / (spec["id"] + ".pdf")
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if snapshot.exists() and file_hash(snapshot) != sha:
            raise ICPError("Source PDF changed in an existing run")
        if not snapshot.exists():
            shutil.copy2(original, snapshot)
        pdf = fitz.open(snapshot)
        toc = pdf.get_toc()
        registry.append({**spec, "sha256": sha, "page_count": len(pdf), "toc": toc, "snapshot": str(snapshot)})
        pages = []
        for index, page in enumerate(pdf):
            number = index + 1
            page_id = "%s.p%05d" % (spec["id"], number)
            image = docroot / "screenshots" / (page_id + ".png")
            image.parent.mkdir(parents=True, exist_ok=True)
            pix = page.get_pixmap(matrix=fitz.Matrix(config["document"]["render_scale"], config["document"]["render_scale"]), colorspace=fitz.csRGB, alpha=False)
            atomic_write(image, pix.tobytes("png"))
            native = page.get_text("text", sort=True)
            atomic_write(docroot / "pages" / (page_id + ".native.md"), native)
            text, backend = native, "native"
            preferred = config["document"]["ocr_backend"]
            ocr_config = {**config["document"], "offline": config["offline"]}
            if not text_reliable(native):
                backend = preferred if preferred != "native" else config["document"]["fallback_ocr_backend"]
                try:
                    text = ocr_page(image, backend, ocr_config, docroot / "ocr" / page_id)
                except ICPError as exc:
                    append_jsonl(root / "diagnostics.jsonl", {"stage": "ocr", "page": page_id, "description": str(exc)})
                    fallback = config["document"]["fallback_ocr_backend"]
                    if backend == fallback:
                        raise
                    backend = fallback
                    text = ocr_page(image, backend, ocr_config, docroot / "ocr" / page_id)
            elif config["document"].get("layout_backend") == "paddle":
                layout_text = ocr_page(image, "paddle", ocr_config, docroot / "layout" / page_id)
                if layout_text.strip() != text.strip():
                    atomic_write(docroot / "pages" / (page_id + ".layout.md"), layout_text)
                    text += "\n\n### PP-StructureV3 layout/table OCR (additional view)\n" + layout_text
            atomic_write(docroot / "pages" / (page_id + ".md"), text)
            # Vision processes every complete page, including vectors; no embedded-image heuristic.
            interpretation = model.call("vision", "reconstruction", {"document_id": spec["id"], "page_number": number,
                                "page_markdown": text, "previous_page_markdown": pages[-1]["text"] if pages else ""}, [image])
            continuations = interpretation.get("page_continuations", {})
            if (interpretation.get("document_id") != spec["id"] or interpretation.get("page_number") != number or
                not isinstance(interpretation.get("items"), list) or not isinstance(interpretation.get("uncertainties"), list) or
                not isinstance(continuations.get("continues_from_previous"), bool) or not isinstance(continuations.get("continues_to_next"), bool)):
                raise ICPError("Invalid vision result for " + page_id, "model_format", True)
            save_json(docroot / "visual_descriptions" / (page_id + ".json"), interpretation)
            merged = text + "\n\n### Whole-page visual interpretation (not verbatim source)\n" + json.dumps(interpretation, ensure_ascii=False)
            pages.append({"id": page_id, "number": number, "text": merged, "page_text": text,
                          "visual_interpretation": interpretation, "native_text": native,
                          "image": str(image.relative_to(root)), "ocr_backend": backend,
                          "continues_from_previous": continuations["continues_from_previous"],
                          "continues_to_next": continuations["continues_to_next"]})
        # Preserve the PDF bookmark hierarchy when present, and independently
        # ask for semantic page boundaries in bounded overlapping-safe windows.
        anchors = [{"page": p, "heading": title, "level": level} for level, title, p in toc if 1 <= p <= len(pages)]
        if not anchors:
            anchors = [{"page": p["number"], "heading": line.strip(), "level": 1}
                       for p in pages for line in p["native_text"].splitlines()
                       if re.match(r"^\d+(?:\.\d+)*\s+[A-Z][^\n]{2,120}$", line.strip())]
        if not anchors:
            anchors = [{"page": 1, "heading": "Document", "level": 1}]
        semantic_starts = _semantic_boundaries(pages, config, model, spec["id"], root)
        anchors.extend({"page": p, "heading": "Model-identified section boundary", "level": 1} for p in semantic_starts)
        starts = sorted(set([1] + [a["page"] for a in anchors]))
        consumed_until = 0
        for position, declared_start in enumerate(starts):
            start = max(declared_start, consumed_until + 1)
            if start > (starts[position + 1] - 1 if position + 1 < len(starts) else len(pages)):
                continue
            end = starts[position + 1] - 1 if position + 1 < len(starts) else len(pages)
            if end < start:
                continue
            section_pages = pages[start - 1:end]
            # Stable heading and page boundaries cap context size. A visually detected
            # cross-page continuation keeps adjacent table pages together.
            chunks, current, chars = [], [], 0
            budget = max(1000, int(config["document"]["max_context_chars"] * .55))
            heading_pages = {a["page"] for a in anchors}
            for page in section_pages:
                page_chars = len(page["text"])
                if page_chars > budget:
                    raise ICPError("A single rendered specification page exceeds the configured context budget; raise the limit or process that page with a larger-context model")
                starts_heading = page["number"] in heading_pages and current and not page["continues_from_previous"]
                full = current and (chars + page_chars > budget or len(current) >= config["document"]["secondary_split_pages"] or starts_heading)
                if full and not current[-1]["continues_to_next"]:
                    chunks.append(current); current, chars = [], 0
                current.append(page); chars += page_chars
            if current:
                chunks.append(current)
            if chunks and chunks[-1][-1]["continues_to_next"]:
                while chunks[-1][-1]["continues_to_next"] and chunks[-1][-1]["number"] < len(pages):
                    next_page = pages[chunks[-1][-1]["number"]]
                    chunks[-1].append(next_page)
                    if sum(len(item["text"]) for item in chunks[-1]) > config["document"]["max_context_chars"] * .9:
                        raise ICPError("A cross-page table exceeds the configured model context; preserve it and increase the model context budget")
                if chunks[-1][-1]["continues_to_next"]:
                    raise ICPError("A cross-page table remains open at the end of the PDF; preserve original pages and report the incomplete relation")
            for chunk in chunks:
                first, last = chunk[0]["number"], chunk[-1]["number"]
                sid = "%s.segment.%d-%d" % (spec["id"], first, last)
                heading = [a["heading"] for a in anchors if a["page"] <= first][-4:]
                body = "\n\n".join("<!-- %s / PDF page %d -->\n%s" % (spec["id"], p["number"], p["text"]) for p in chunk)
                label = model.call("text", "relevance", {"segment_id": sid, "heading_path": heading, "markdown": body})
                if label.get("relevance") not in ("relevant", "auxiliary"):
                    raise ICPError("Invalid relevance annotation")
                source_ids = []
                for p in chunk:
                    identity = "source." + p["id"]
                    sources[identity] = {"document_id": spec["id"], "document_hash": sha, "page_number": p["number"],
                                         "segment_id": sid, "heading_path": heading, "text": p["page_text"],
                                         "visual_interpretation": p["visual_interpretation"],
                                         "screenshot": p["image"], "visual_description_id": p["id"], "ocr_backend": p["ocr_backend"]}
                    source_ids.append(identity)
                relative = "document/segments/" + sid + ".md"
                atomic_write(root / relative, body)
                prior_segment = segments[-1]["segment_id"] if segments and segments[-1]["document_id"] == spec["id"] else None
                segments.append({"segment_id": sid, "document_id": spec["id"], "parent_segment_id": prior_segment,
                                 "heading_path": heading, "page_start": first, "page_end": last, "markdown_path": relative,
                                 "relevance": label["relevance"], "source_refs": source_ids})
                full.append("# " + sid + " [" + label["relevance"] + "]\n" + body)
                consumed_until = last
        pdf.close()
    save_json(docroot / "documents.json", registry)
    save_json(docroot / "sources.json", sources)
    atomic_write(docroot / "segments.jsonl", b"".join(json.dumps(s, ensure_ascii=False).encode() + b"\n" for s in segments))
    atomic_write(docroot / "full_specification.md", "\n\n".join(full))
    return sources, segments
