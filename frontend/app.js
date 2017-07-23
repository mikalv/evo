function generateVotes(number) {
    let votes = []
    for (let i = 0; i < number; i++) {
        votes.push('vote#' + i)
    }

    return votes
}

window.onload = () => {
    let field = document.getElementById('field')
    let time = document.getElementById("time")
    let neff = document.getElementById('neff')
    let sato = document.getElementById('sato')
    let parallel = document.getElementById('parallel')

    const socket = new WebSocket('ws://localhost:8000/ws')

    socket.onmessage = (event) => {
        time.innerHTML = ''
        time.append(event.data)
    }

    document.getElementById('button').addEventListener('click', () => {
        let query = {
            votes: generateVotes(field.value),
            algorithm: neff.checked ? 'neff' : 'sato',
            parallelize: parallel.checked ? true : false
        }

        socket.send(JSON.stringify(query))
    })
}
