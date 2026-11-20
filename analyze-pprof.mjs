import fs from 'node:fs';
import zlib from 'node:zlib';
function varint(buffer,state){let value=0n,shift=0n;while(state.i<buffer.length){const b=buffer[state.i++];value|=BigInt(b&127)<<shift;if(!(b&128))return Number(value);shift+=7n;if(shift>70n)throw Error('Invalid varint');}throw Error('Truncated varint');}
function fields(buffer){const state={i:0},rows=[];while(state.i<buffer.length){const tag=varint(buffer,state),wire=tag&7,field=tag>>3;let value;if(wire===0)value=varint(buffer,state);else if(wire===2){const size=varint(buffer,state);value=buffer.subarray(state.i,state.i+size);state.i+=size;}else if(wire===1){value=buffer.subarray(state.i,state.i+8);state.i+=8;}else if(wire===5){value=buffer.subarray(state.i,state.i+4);state.i+=4;}else throw Error('Unknown wire '+wire);rows.push({field,wire,value});}return rows;}
const all=(rows,id)=>rows.filter(r=>r.field===id).map(r=>r.value);
const first=(rows,id)=>all(rows,id)[0]??0;
function numbers(rows,id){return rows.filter(r=>r.field===id).flatMap(r=>{if(r.wire===0)return [r.value];const state={i:0},values=[];while(state.i<r.value.length)values.push(varint(r.value,state));return values;});}
export function analyze(path){
 const profile=fields(zlib.gunzipSync(fs.readFileSync(path)));const strings=all(profile,6).map(b=>b.toString());
 const types=all(profile,1).map(b=>{const f=fields(b);return {type:strings[first(f,1)],unit:strings[first(f,2)]};});
 const index=types.findIndex(t=>t.type==='cpu'&&t.unit==='nanoseconds');if(index<0)throw Error('No CPU nanoseconds samples');
 const functions=new Map(all(profile,5).map(b=>{const f=fields(b);return [first(f,1),strings[first(f,2)]];}));
 const locations=new Map(all(profile,4).map(b=>{const f=fields(b);return [first(f,1),all(f,4).map(line=>functions.get(first(fields(line),1))||'[unknown]')];}));
 const flat=new Map(),cumulative=new Map();let total=0,samples=0;
 for(const b of all(profile,2)){
  const f=fields(b),value=numbers(f,2)[index];if(!Number.isFinite(value))throw Error('Bad sample');
  const stack=numbers(f,1).flatMap(id=>locations.get(id)||['[unknown]']);total+=value;samples++;
  flat.set(stack[0],(flat.get(stack[0])||0)+value);
  for(const name of new Set(stack))cumulative.set(name,(cumulative.get(name)||0)+value);
 }
 const sort=map=>[...map].sort((a,b)=>b[1]-a[1]).map(([name,value])=>({name,seconds:value/1e9,percent:100*value/total}));
 return {duration_seconds:first(profile,10)/1e9,cpu_seconds:total/1e9,samples,types,flat:sort(flat),cumulative:sort(cumulative)};
}
if(process.argv[1]?.endsWith('analyze-pprof.mjs'))console.log(JSON.stringify(analyze(process.argv[2]),null,2));
