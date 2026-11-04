const notes = new Map();
let nextId = 1;

module.exports = {
  list: () => [...notes.values()],
  save(note) {
    const saved = { ...note, id: nextId++ };
    notes.set(saved.id, saved);
    return saved;
  },
  remove: (id) => notes.delete(id),
};
