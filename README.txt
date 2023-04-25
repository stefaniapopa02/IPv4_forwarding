Popa Stefania, 323CD

In cadrul temei, am rezolvat urmatoarele cerinte: protocolul ARP, procesul
de dirijare si protocolul ICMP. Am implementat si LPM eficient si suma de control 
incrementala, dar, din pacate, nu mi-a ajuns timpul pentru a gasi bug-urile
si a le face functionale.

Pe tot parcursul implementarii, am urmarit pasii din cerinta temei.
In functia main, initializez coada de pacete si aloc cache-ul(pentru 
intrarile arp) si tabela de rutare(pe care o extragdin parametri functiei 
main).

Dupa primirea pachetului, verific ca acesta sa nu aiba o lungime prea mica,
dupa care, extrag adresele ip si mac curente.

Implementarea este impartita in doua mari cazuri, in functie de tipul 
header-ului ethernet:

---->ARP
    Daca acesta este un request si imi este destinat mie, atunci il 
    transform intr un reply si actualizez datelepentru a putea trimite 
    pachetul mai departe.
    Daca este de tipl reply, ii furnizez datele cerute, adica corespondenta
    dintre adresa ip si adresa mac, pe care o adaug in cache. Acum pot 
    scoate pachet din coada, pentru a-i completa adresa mac asteptata si
    pentru a-l putea trimite mai departe.

---->IPv4
    Daca este un mesaj de tip icmp destinat router-ului, voi trimite inapoi
    un pachet icmp reply cu datele actualizate.
    Altfel, recalculez checksum-ul si verific sa corespunda cu cel din
    cadrul pachetului. Verific si campul ttl; daca acesta a expirat, trimit
    un mesaj icmp de tip eroare time exceed.Pentru acest lucru, pastrez 
    header-ul de ethernet si cel ip, la care adaug header-ul icmp si abia apoi
    payload-ul pe care il continea IP-ul. Pentru aceasta va fi nevoie sa deplasam
    payload-ul cu lungimea icmp-ului(4 octeti), pentru a-i face loc acestuia
    in pachet.
    Altfel, decrementam ttl-ul si cautam in tabela de rutare urmatorul hop, folosind
    functia get_next_hop.
    Daca nu exista ruta pana la destinatie, vom trimite un mesaj icmp de tip
    eroare "Destination unreacheable"(procedam la fel ca pt cazul "Time exceed").
    Deoarece ttl-ul a fost schimbat, recalculam checksum-ul, iar apoi cautam mac-ul 
    pentru ip-ul next-hop-ului gasit.
    Daca mac-ul nu exista in cache, vom pune pachetul in coada(unde isi va astepta 
    adrea mac) si vom trimte un pachet arp de tip request. Acesta va fi trimis prin 
    broadcast, pentru toata lumea, cautand mac-ul corespunzator adresei ip.
    Daca mac-ul cautat se afla deja in cache, doar completam pachetul si apoi il 
    trimitem mai departe.

Functia get_best_route este varianta de cautare liniara a LPM-ului,
in timp ce binary_search este varianta de cautare binara a LPM-ului eficient.
Pentru acesta din urma am sortat tabel de rutare cu qsort, folosindu-ma de 
functia de comparare comparator.
Functia get_arp_entry cauta in cache mac-ul corespunzator unei adrese ip date 
ca parametru. Daca aceasta corespondenta nu exista momentan in cache, functia
va returna NULL.
Functia incr_checksum este cea care implementeaza suma de control incrementala,
cu formula gasita in RFC1624.