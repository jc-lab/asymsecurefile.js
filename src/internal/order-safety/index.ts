export type RunFunction<T> = () => PromiseLike<T> | T;

interface IWorkQueueItem<T> {
  fn: RunFunction<T>;
  resolve: () => T;
  reject: (err: any) => void;
}

function removeReduce<T>(arr: T[], reducer: (chain: T, item: T) => T, initial: T): T {
  let prev = initial;
  arr.forEach((item: T, index: number, object: T[]) => {
    prev = reducer(prev, item);
    object.splice(index, 1);
  });
  return prev;
}

export default class OrderSafety {
  private _lock: number = 0;
  private _workQueue: IWorkQueueItem<any>[] = [];

  private _runQueue(): Promise<void> {
    return removeReduce<any>(this._workQueue,
      (chain, item) => chain.finally(() => new Promise((resolve) => {
        Promise.resolve(item.fn())
          .then(() => {
            item.resolve();
          })
          .catch((e) => {
            item.reject(e);
          })
          .finally(resolve);
      })),
      Promise.resolve()).then(() => {
      if (this._workQueue.length > 0) {
        this._runQueue();
      }
    });
  }

  run<T>(fn: RunFunction<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this._workQueue.push({
        fn,
        resolve,
        reject
      });
      this._dequeue();
    });
  }

  private _dequeue() {
    if (this._lock) {
      return ;
    }
    const item = this._workQueue.shift();
    if (!item) {
      return ;
    }
    try {
      this._lock = 1;
      Promise.resolve(item.fn())
        .then(item.resolve)
        .catch(item.reject)
        .finally(() => {
          this._lock = 0;
          this._dequeue();
        });
    } catch (e) {
      item.reject(e);
      this._lock = 0;
      this._dequeue();
    }
  }
}
