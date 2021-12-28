const url = document.getElementById("url");
const submitBtn = document.getElementById("short");

// url.addEventListener("focus", () => {
//   url.value = "";
//   document.getElementById("status").innerText = "";
//   document.getElementById("status").style.color = "black";
//   document.getElementsByClassName("sURL")[0].setAttribute("href", "");
//   document.getElementsByClassName("sURL")[0].innerHTML = "";
//   document.getElementsByClassName("safety")[0].innerHTML = "URL Safe:";
// })

submitBtn.addEventListener("click", (e) => {
  console.log("Btn clicked!");
  e.preventDefault();
  const urlValue = url.value;
  let isUrlValid;

  if (!Boolean(urlValue)) {
    console.log("Enter valid URL");
    return;
  }

  fetch(urlValue)
    .then((response) => {
      if (response.status >= 200 && response.status < 300) {
        console.log("URL Exists");
        isUrlValid = true;
      } else {
        console.log("URL Doesn't exits");
        isUrlValid = false;
      }
    })
    .then(() => {
      if (isUrlValid) {
        getId(urlValue);
      }
    })
    .catch((error) => {
      console.log("URL Doesn't exits", error);
    });
});

function getId(urlValue) {
  const options = {
    method: "POST",
    headers: {
      Accept: "application/json",
      "x-apikey":
        "6d96efe421861509b0b7ec99c33a98a7671b0b0d2c3af7d4f31eb31256796502",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ url: urlValue }),
  };

  fetch("https://www.virustotal.com/api/v3/urls", options)
    .then((response) => response.json())
    .then((response) => {
      if (response) {
        console.log(response);
        const data = response.data;
        if (data == undefined) {
          document.getElementById("status").innerText = "Error!!!";
          document.getElementById("myH2").style.color = "red";
          return;
        }
        const ID = data.id;
        getData(ID, urlValue);
      }
    })
    .catch((err) => console.error(err));
}

function getData(id, urlValue) {
  const options = {
    method: "GET",
    headers: {
      Accept: "application/json",
      "x-apikey":
        "6d96efe421861509b0b7ec99c33a98a7671b0b0d2c3af7d4f31eb31256796502",
    },
  };
  fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, options)
    .then((response) => response.json())
    .then((response) => {
      const analysis = response.data;
      console.log(analysis);
      printData(analysis, urlValue);
      if (analysis.attributes.status == "queued") {
        document.getElementById("status").innerText = "Processing...";
        getId(urlValue);
        return;
      }
    })
    .catch((err) => console.error(err));
}

function printData(urlData, urlValue) {
  const harmless = urlData.attributes.stats.harmless;
  const malicious = urlData.attributes.stats.malicious;

  if ((harmless !== 0 || malicious !== 0) && harmless > malicious) {
    document.getElementsByClassName("safety")[0].innerHTML = "URL Safe: ✅";
    getShortUrl(urlValue);
  } else if ((harmless !== 0 || malicious !== 0) && harmless < malicious) {
    document.getElementsByClassName("safety")[0].innerHTML = "URL Safe:  ❌";
    document.getElementById("status").innerText = "Enter a Safe URL";
    document.getElementById("status").style.color = "red";
  }
}

function getShortUrl(urlValue) {
  fetch("https://api-ssl.bitly.com/v4/shorten", {
    method: "POST",
    headers: {
      Authorization: "Bearer c46d9bc50d7d73df3acce33edbe612fd6f305f31",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ long_url: urlValue, domain: "bit.ly" }),
  }).then((response) =>
    response.json().then((data) => {
      const shortedUrl = data.id;
      document.getElementById("status").innerText = "URL shortened";
      document.getElementById("status").style.color = "green";
      document
        .getElementsByClassName("sURL")[0]
        .setAttribute("href", "http://" + shortedUrl);
      document.getElementsByClassName("sURL")[0].innerHTML = shortedUrl;
    })
  );
}

// function copyURL() {
//   window.copied = document.getElementById("copy");
//   copied.select();
//   // copied.setSelectionRange(0, 99999);
//   navigator.clipboard.writeText(shortUrl);
//   // document.getElementById("copy").innerHtml=copied;
// }

// function getp() {
//   // START
//   // fetch("/", {
//   //   method: "POST",
//   //   headers: {'Content-Type': 'application/json'},
//   // }).then(res => {
//   //   console.log("Request complete! response:", res.status);
//   // });

//   // // END
//   if (urll === "" || !Boolean(urll)) {
//     document.getElementById("status").innerText = "Enter a Valid URL";
//     document.getElementById("status").style.color = "red";
//     urll.value = "";
//     return;
//   }
// }
