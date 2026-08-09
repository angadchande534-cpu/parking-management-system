function toggleNav(){
  const nav=document.querySelector('.nav');
  if(nav) nav.classList.toggle('show');
}
setTimeout(()=>{
  const t=document.getElementById('toast');
  if(t) t.style.display='none';
},3500);

async function refreshAvailability(){
  try{
    const r=await fetch('/api/availability');
    const d=await r.json();
    const map={
      availableSlots:d.total_available,
      occupiedSlots:d.occupied,
      carAvailable:d.car_available,
      bikeAvailable:d.bike_available,
      homeAvailable:d.total_available,
      homeOccupied:d.occupied
    };
    Object.entries(map).forEach(([id,val])=>{
      const el=document.getElementById(id);
      if(el) el.textContent=val;
    });
  }catch(e){}
}
refreshAvailability();
setInterval(refreshAvailability,10000);
