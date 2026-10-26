// Progressive enhancement for walkthrough screenshots: without JS the links open the image.
(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll("a.shot-link"));
  if (!links.length || typeof HTMLDialogElement === "undefined") return;

  var dlg = document.createElement("dialog");
  dlg.className = "lightbox";
  dlg.setAttribute("aria-label", "Screenshot");
  dlg.innerHTML =
    '<div class="lightbox-body">' +
    '<div class="lightbox-bar"><span></span><button type="button" data-act="close">Close</button></div>' +
    '<img alt="">' +
    '<p></p>' +
    '<div class="lightbox-bar"><button type="button" data-act="prev">Previous</button><button type="button" data-act="next">Next</button></div>' +
    '</div>';
  document.body.appendChild(dlg);

  var img = dlg.querySelector("img");
  var cap = dlg.querySelector("p");
  var count = dlg.querySelector(".lightbox-bar span");
  var index = -1;
  var trigger = null;

  function show(i) {
    index = (i + links.length) % links.length;
    var a = links[index];
    var thumb = a.querySelector("img");
    img.src = a.getAttribute("href");
    img.width = thumb ? thumb.getAttribute("width") : 0;
    img.height = thumb ? thumb.getAttribute("height") : 0;
    img.alt = thumb ? thumb.alt : "";
    cap.textContent = thumb ? thumb.alt : "";
    count.textContent = (index + 1) + " of " + links.length;
  }

  links.forEach(function (a, i) {
    a.addEventListener("click", function (e) {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      trigger = a;
      show(i);
      dlg.showModal();
    });
  });

  dlg.addEventListener("click", function (e) {
    var act = e.target.getAttribute && e.target.getAttribute("data-act");
    if (act === "close" || e.target === dlg) dlg.close();
    else if (act === "prev") show(index - 1);
    else if (act === "next") show(index + 1);
  });
  dlg.addEventListener("keydown", function (e) {
    if (e.key === "ArrowLeft") { e.preventDefault(); show(index - 1); }
    else if (e.key === "ArrowRight") { e.preventDefault(); show(index + 1); }
  });
  dlg.addEventListener("close", function () {
    img.removeAttribute("src");
    if (trigger) trigger.focus();
  });
})();
