/*===== SHOW NAVBAR  =====*/
const showNavbar = (toggleId, navId, bodyId, headerId) => {
    const toggle = document.getElementById(toggleId),
        nav = document.getElementById(navId),
        bodypd = document.getElementById(bodyId),
        headerpd = document.getElementById(headerId)

    // Validate that all variables exist
    if (toggle && nav && bodypd && headerpd) {
        toggle.addEventListener('click', () => {
            // show navbar
            nav.classList.toggle('show')
            // change icon
            toggle.classList.toggle('bx-x')
            // add padding to body
            bodypd.classList.toggle('body-pd')
            // add padding to header
            headerpd.classList.toggle('body-pd')
        })
    }
}

function getEventTarget(e) {
    e = e || window.event;
    return e.target || e.srcElement;
}

function enable_div_menu(div_name) {
    document.getElementById("enviroment_id").style.display = "none";
    document.getElementById("chart_id").style.display = "none";
    // document.getElementById("control_id").style.display = "none";
    document.getElementById("history_id").style.display = "none";
    // document.getElementById("mender_update_id").style.display = "none";
    document.getElementById(div_name).style.display = "block";
}

const menu = document.getElementById("menu")
menu.onclick = function (event) {
    var target = getEventTarget(event);
    console.log("chart")
    if (target.id == "menu_info_enviroment") {
        enable_div_menu("enviroment_id")
    } else if (target.id == "menu_chart") {
        
        enable_div_menu("chart_id")
    } else if (target.id == "menu_control") {
        enable_div_menu("control_id")
    } else if (target.id == "menu_history") {
        enable_div_menu("history_id")
    } else if (target.id == "menu_update") {
        enable_div_menu("mender_update_id")
    }
}

showNavbar('header-toggle', 'nav-bar', 'body-pd', 'header')

/*===== LINK ACTIVE  =====*/
const linkColor = document.querySelectorAll('.nav__link')

function colorLink() {
    if (linkColor) {
        linkColor.forEach(l => l.classList.remove('active'))
        this.classList.add('active')
    }
}
linkColor.forEach(l => l.addEventListener('click', colorLink))