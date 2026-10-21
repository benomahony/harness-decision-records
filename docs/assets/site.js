// Copy buttons for code blocks and the hero install command.
function copyText(button, text) {
  console.assert(button instanceof HTMLElement, "Copy needs a button", button)
  console.assert(typeof text === "string" && text.length > 0, `Nothing to copy (length=${text?.length})`)
  navigator.clipboard.writeText(text).then(() => {
    const label = button.textContent
    button.textContent = "Copied"
    setTimeout(() => { button.textContent = label }, 1400)
  }).catch(() => { button.textContent = "Select to copy" })
}

// Give headings stable ids and list them in the "On this page" panel.
function buildToc() {
  console.assert(document.readyState !== "loading", `Build the TOC after parsing (readyState=${document.readyState})`)
  const list = document.querySelector(".toc-list")
  const headings = document.querySelectorAll(".prose h2:not(.block h2), .prose h3:not(.block h3)")
  if (!list || headings.length === 0) {
    document.querySelector(".toc")?.classList.add("empty")
    return
  }
  for (const heading of headings) {
    heading.id ||= heading.textContent.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "")
    const item = document.createElement("li")
    item.className = heading.tagName === "H3" ? "sub" : ""
    const link = document.createElement("a")
    link.href = `#${heading.id}`
    link.textContent = heading.textContent
    item.appendChild(link)
    list.appendChild(item)
  }
  const links = new Map([...list.querySelectorAll("a")].map((a) => [a.hash.slice(1), a]))
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue
      for (const a of links.values()) a.classList.remove("current")
      links.get(entry.target.id)?.classList.add("current")
    }
  }, { rootMargin: "-80px 0px -70% 0px" })
  for (const heading of headings) observer.observe(heading)
  console.assert(list.children.length === headings.length, "TOC lost headings", list.children.length)
}

document.addEventListener("DOMContentLoaded", () => {
  buildToc()
  for (const button of document.querySelectorAll("button.copy[data-copy]")) {
    button.addEventListener("click", () => copyText(button, button.dataset.copy))
  }
  for (const pre of document.querySelectorAll(".prose pre, .step pre")) {
    const button = document.createElement("button")
    button.type = "button"
    button.className = "copy floating"
    button.textContent = "Copy"
    button.addEventListener("click", () => copyText(button, pre.querySelector("code")?.innerText ?? pre.innerText))
    pre.appendChild(button)
  }
})
