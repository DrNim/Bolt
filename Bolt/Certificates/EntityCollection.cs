using System;
using System.Collections;
using System.Collections.Generic;

namespace Bolt
{

    public sealed class EntityCollection : ICollection<Entity>
    {

        #region " Properties "

        public int Count
        {
            get { return _items.Count; }
        }

        public bool IsReadOnly
        {
            get { return false; }
        }

        #endregion

        #region " Members "

        private List<Entity> _items;

        #endregion

        #region " Constructor "

        public EntityCollection()
        {
            _items = new List<Entity>();
        }

        #endregion

        #region " Modify "

        public void Add(Entity item)
        {
            if (item == null)
            {
                throw new ArgumentNullException(nameof(item));
            }

            if (Contains(item))
            {
                throw new ArgumentException("Element already exists in the collection.");
            }

            _items.Add(item);
        }

        public bool Remove(Entity item)
        {
            return _items.Remove(item);
        }

        public void Clear()
        {
            _items.Clear();
        }

        #endregion

        #region " Read "

        public bool Contains(Entity item)
        {
            return _items.Contains(item);
        }

        public void CopyTo(Entity[] array, int arrayIndex)
        {
            _items.CopyTo(array, arrayIndex);
        }

        public IEnumerator<Entity> GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        #endregion

    }

}
